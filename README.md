# proxychain

**We don't recommend you to use this software until version 0.1.0 or higher.**

Proxychain is a command-line tool for converting proxy protocols and creating proxy chain. 

## Example

Suppose you have a HTTP proxy listening on 8123 port of your local machine, you can use following command to convert it to a SOCKS5 proxy:

```
proxychain -i socks5://127.0.0.1:9000 -o http://127.0.0.1:8123
```

## Protocol Support

- [x] HTTP Tunnel without authentication to SOCKS5

## To-do

- [ ] Support HTTP authentication
- [ ] Support SOCKS5 to HTTP
- [ ] Multi-thread
- [ ] Proxy Chain