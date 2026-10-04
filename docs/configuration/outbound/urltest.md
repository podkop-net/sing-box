### Structure

```json
{
  "type": "urltest",
  "tag": "auto",
  
  "outbounds": [
    "proxy-a",
    "proxy-b",
    "proxy-c"
  ],
  "url": "",
  "download_url": "",
  "interval": "",
  "tolerance": 0,
  "idle_timeout": "",
  "interrupt_exist_connections": false
}
```

### Fields

#### outbounds

==Required==

List of outbound tags to test.

#### url

The URL to test. `https://www.gstatic.com/generate_204` will be used if empty.

#### download_url

!!! info "podkop-engine r10"

The URL of the download test. Before the group switches to a member, it downloads 64 KiB from
this URL through the member; a member whose download stops on the way is passed over until its
next test result. The URL must serve at least 64 KiB, or announce a shorter length.

| Value              | Download test                                                         |
|--------------------|-----------------------------------------------------------------------|
| (absent)           | The URL in the `SING_BOX_URLTEST_DOWNLOAD_URL` environment variable, off without it |
| `""`               | Off for this group                                                    |
| `http`/`https` URL | This URL                                                              |

#### interval

The test interval. `3m` will be used if empty.

#### tolerance

The test tolerance in milliseconds. `50` will be used if empty.

#### idle_timeout

The idle timeout. `30m` will be used if empty.

#### interrupt_exist_connections

Interrupt existing connections when the selected outbound has changed.

Only inbound connections are affected by this setting, internal connections will always be interrupted.
