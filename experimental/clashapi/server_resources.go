package clashapi

import (
	"archive/zip"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/ntp"
	"github.com/sagernet/sing/service/filemanager"
)

func (s *Server) checkAndDownloadExternalUI() {
	if s.externalUI == "" {
		return
	}
	entries, err := filemanager.ReadDir(s.ctx, s.externalUI)
	if err != nil {
		filemanager.MkdirAll(s.ctx, s.externalUI, 0o755)
	}
	if len(entries) == 0 {
		err = s.downloadExternalUI()
		if err != nil {
			s.logger.Error("download external ui error: ", err)
		}
	}
}

func (s *Server) downloadExternalUI() error {
	var downloadURL string
	if s.externalUIDownloadURL != "" {
		downloadURL = s.externalUIDownloadURL
	} else {
		downloadURL = "https://github.com/MetaCubeX/Yacd-meta/archive/gh-pages.zip"
	}
	var detour adapter.Outbound
	if s.externalUIDownloadDetour != "" {
		outbound, loaded := s.outbound.Outbound(s.externalUIDownloadDetour)
		if !loaded {
			return E.New("detour outbound not found: ", s.externalUIDownloadDetour)
		}
		detour = outbound
	} else {
		outbound := s.outbound.Default()
		detour = outbound
	}
	s.logger.Info("downloading external ui using outbound/", detour.Type(), "[", detour.Tag(), "]")
	httpClient := &http.Client{
		Transport: &http.Transport{
			ForceAttemptHTTP2:   true,
			TLSHandshakeTimeout: C.TCPTimeout,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return detour.DialContext(ctx, network, M.ParseSocksaddr(addr))
			},
			TLSClientConfig: &tls.Config{
				Time:    ntp.TimeFuncFromContext(s.ctx),
				RootCAs: adapter.RootPoolFromContext(s.ctx),
			},
		},
	}
	defer httpClient.CloseIdleConnections()
	response, err := httpClient.Get(downloadURL)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return E.New("download external ui failed: ", response.Status)
	}
	return s.downloadZIP(response.Body, s.externalUI)
}

func (s *Server) downloadZIP(body io.Reader, output string) error {
	tempFile, err := filemanager.CreateTemp(s.ctx, "external-ui.zip")
	if err != nil {
		return err
	}
	defer filemanager.Remove(s.ctx, tempFile.Name())
	_, err = io.Copy(tempFile, body)
	tempFile.Close()
	if err != nil {
		return err
	}
	return extractExternalUI(s.ctx, tempFile.Name(), output)
}

// externalUIStaging is the directory inside the external UI directory that an archive is
// unpacked into before its files replace those served.
const externalUIStaging = ".external-ui-update"

// extractExternalUI unpacks the archive into a directory of its own inside output, and puts
// what it unpacked in place of the other files of output only when all of it is there: an
// archive that fails to unpack (no space left, a broken or an empty archive) leaves the
// files that were served. The directory is inside output to be on its file system, a mount
// point or a symbolic link included: the files are moved into place, not copied.
func extractExternalUI(ctx context.Context, archive string, output string) error {
	reader, err := zip.OpenReader(archive)
	if err != nil {
		return err
	}
	defer reader.Close()
	staging := filepath.Join(output, externalUIStaging)
	// left by an update that did not end
	err = filemanager.RemoveAll(ctx, staging)
	if err != nil {
		return err
	}
	err = unpackZIP(ctx, reader.File, staging)
	if err != nil {
		filemanager.RemoveAll(ctx, staging)
		return err
	}
	return replaceWithStaging(ctx, output, staging)
}

func unpackZIP(ctx context.Context, files []*zip.File, output string) error {
	trimDir := zipIsInSingleDirectory(files)
	var unpacked int
	for _, file := range files {
		if file.FileInfo().IsDir() {
			continue
		}
		pathElements := strings.Split(file.Name, "/")
		if trimDir {
			pathElements = pathElements[1:]
		}
		name := filepath.Join(pathElements...)
		if !filepath.IsLocal(name) || pathElements[0] == externalUIStaging {
			return E.New("invalid path in archive: ", file.Name)
		}
		savePath := filepath.Join(output, name)
		err := filemanager.MkdirAll(ctx, filepath.Dir(savePath), 0o755)
		if err != nil {
			return err
		}
		err = downloadZIPEntry(ctx, file, savePath)
		if err != nil {
			return err
		}
		unpacked++
	}
	if unpacked == 0 {
		return E.New("no files in archive")
	}
	return nil
}

// replaceWithStaging puts the files of staging, a directory inside directory, in place of
// the other files of directory.
func replaceWithStaging(ctx context.Context, directory string, staging string) error {
	entries, err := filemanager.ReadDir(ctx, directory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Name() == externalUIStaging {
			continue
		}
		err = filemanager.RemoveAll(ctx, filepath.Join(directory, entry.Name()))
		if err != nil {
			return err
		}
	}
	entries, err = filemanager.ReadDir(ctx, staging)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		err = filemanager.Rename(ctx, filepath.Join(staging, entry.Name()), filepath.Join(directory, entry.Name()))
		if err != nil {
			return err
		}
	}
	return filemanager.Remove(ctx, staging)
}

func downloadZIPEntry(ctx context.Context, zipFile *zip.File, savePath string) error {
	saveFile, err := filemanager.Create(ctx, savePath)
	if err != nil {
		return err
	}
	defer saveFile.Close()
	reader, err := zipFile.Open()
	if err != nil {
		return err
	}
	defer reader.Close()
	return common.Error(io.Copy(saveFile, reader))
}

func zipIsInSingleDirectory(files []*zip.File) bool {
	var singleDirectory string
	for _, file := range files {
		if file.FileInfo().IsDir() {
			continue
		}
		pathElements := strings.Split(file.Name, "/")
		if len(pathElements) == 0 {
			return false
		}
		if singleDirectory == "" {
			singleDirectory = pathElements[0]
		} else if singleDirectory != pathElements[0] {
			return false
		}
	}
	return true
}
