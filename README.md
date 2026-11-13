# OmbiFix

`ombi_fix.py` is a thin Jellyfin 10.11.x -> 12.x compatibility shim for Ombi 4.53.x.

Point Ombi's Jellyfin server settings at this proxy instead of at Jellyfin.
The proxy speaks the Jellyfin 10.11.11 API that Ombi expects and forwards
each request to a real Jellyfin 12 server.

```sh
python3 ombi_fix.py --upstream https://jellyfin.example.com [--port 8097]
```

FYI: this proxy serves a HTTP port, regardless of whether the target server is HTTPS or not. 
Disable SSL in your Jellyfin settings in Ombi while using this proxy.
