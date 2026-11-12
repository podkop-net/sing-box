package clashapi

import (
	"archive/zip"
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func writeArchive(t *testing.T, files ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ui.zip")
	file, err := os.Create(path)
	require.NoError(t, err)
	writer := zip.NewWriter(file)
	for _, name := range files {
		entry, err := writer.Create(name)
		require.NoError(t, err)
		if !strings.HasSuffix(name, "/") {
			_, err = entry.Write([]byte("new " + name))
			require.NoError(t, err)
		}
	}
	require.NoError(t, writer.Close())
	require.NoError(t, file.Close())
	return path
}

func listFiles(t *testing.T, directory string) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir(directory, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			relative, _ := filepath.Rel(directory, path)
			files = append(files, filepath.ToSlash(relative))
		}
		return nil
	})
	require.NoError(t, err)
	sort.Strings(files)
	return files
}

func servedDirectory(t *testing.T) string {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "ui")
	require.NoError(t, os.MkdirAll(filepath.Join(directory, "assets"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(directory, "index.html"), []byte("old"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(directory, "assets", "old.js"), []byte("old"), 0o644))
	return directory
}

var oldFiles = []string{"assets/old.js", "index.html"}

func TestExtractExternalUIReplaces(t *testing.T) {
	directory := servedDirectory(t)
	// left by an update that did not end
	require.NoError(t, os.MkdirAll(filepath.Join(directory, externalUIStaging, "x"), 0o755))
	archive := writeArchive(t, "Yacd-meta-gh-pages/", "Yacd-meta-gh-pages/index.html", "Yacd-meta-gh-pages/assets/new.js")
	require.NoError(t, extractExternalUI(context.Background(), archive, directory))
	require.Equal(t, []string{"assets/new.js", "index.html"}, listFiles(t, directory))
	content, err := os.ReadFile(filepath.Join(directory, "index.html"))
	require.NoError(t, err)
	require.Equal(t, "new Yacd-meta-gh-pages/index.html", string(content))
}

func TestExtractExternalUIIntoEmptyDirectory(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "ui")
	require.NoError(t, os.MkdirAll(directory, 0o755))
	archive := writeArchive(t, "index.html", "assets/a.js")
	require.NoError(t, extractExternalUI(context.Background(), archive, directory))
	require.Equal(t, []string{"assets/a.js", "index.html"}, listFiles(t, directory))
}

// An archive that does not unpack leaves the files served as they were, and nothing of it.
func TestExtractExternalUIKeepsServedOnFailure(t *testing.T) {
	broken := filepath.Join(t.TempDir(), "broken.zip")
	require.NoError(t, os.WriteFile(broken, []byte("not a zip"), 0o644))
	for name, archive := range map[string]string{
		"a file where a directory goes": writeArchive(t, "index.html", "assets", "assets/a.js"),
		"a path out of the directory":   writeArchive(t, "index.html", "../escaped.js"),
		"the name of the staging":       writeArchive(t, "index.html", externalUIStaging+"/a.js"),
		"no files":                      writeArchive(t, "dist/"),
		"one file in a single folder":   writeArchive(t, "index.html"),
		"not an archive":                broken,
	} {
		t.Run(name, func(t *testing.T) {
			directory := servedDirectory(t)
			require.Error(t, extractExternalUI(context.Background(), archive, directory))
			require.Equal(t, oldFiles, listFiles(t, directory))
			require.NoFileExists(t, filepath.Join(filepath.Dir(directory), "escaped.js"))
		})
	}
}
