import logging
import io
import asyncio
import struct
import time

logging.basicConfig(level=logging.DEBUG, format='[%(asctime)-15s] [%(levelname)-8s] %(message)s')

backend_map = {
    'www.baidu.com': (None, 443),
    'www.zhihu.com': (None, 443),
    'www.google.com': ('103.6.48.170', 8443),
    'zh.wikipedia.org': ('198.35.26.96', 443),
}


def extract_sni_info(packet):
    time_start = time.time()
    # process as byte stream
    bs = io.BytesIO(packet)
    bs.read(0x26)

    bs.read(ord(bs.read(1))) # session_id
    bs.read(struct.unpack('>h', bs.read(2))[0]) # cipher_suites
    bs.read(ord(bs.read(1))) # compression_methods
    bs.read(2) # extensions_length

    # read extensions: sni etype == 0x0000
    while True:
        etype = bs.read(2)
        if not etype:
            break
        elen, = struct.unpack('>h', bs.read(2))
        edata = bs.read(elen)
        if etype == b'\x00\x00':
            logging.debug('Time for parse sni info: {} millisecs'.format((time.time() - time_start) * 1000))
            return edata[5:].decode()
    return None


def get_backend_info(server_name):
    # 设置了 ip 的通过 ip 连接，否则直接通过 sni 信息连接
    host = server_name if backend_map[server_name][0] is None else backend_map[server_name][0]
    port = backend_map[server_name][1]

    return host, port


async def dial(client_conn, server_conn):
    """dial between client and server"""

    async def io_copy(reader, writer):
        """bytes stream copy"""
        while True:
            data = await reader.read(32)
            if not data:
                break
            writer.write(data)
        writer.close()

    asyncio.ensure_future(io_copy(client_conn[0], server_conn[1]))
    asyncio.ensure_future(io_copy(server_conn[0], client_conn[1]))


def refuse_request(writer):
    """request alert handshake failure"""
    # 0x15 => Content Type: Alert
    # 0x0301 => Version: TLS v1
    # 0x0002 => Length: 2
    # 0x02 => Alert Message Level: Fatal
    # 0x28 => Alert Message Descrption: Handshake Failure
    writer.write(b'\x15\x03\x01\x00\x02\x02\x28')
    writer.close()


async def handle_tls_connection(reader, writer):
    """process tls_v1 request"""
    time_start = time.time()
    peername = writer.get_extra_info('peername')

    # parse client hello data
    client_hello_header = await reader.read(5)

    # accept tls_v1 request only
    if not client_hello_header.startswith(b'\x16\x03\x01'):
        refuse_request(writer)

    client_hello_len, = struct.unpack('>h', client_hello_header[3:])
    logging.debug('Client Hello Length: {}'.format(client_hello_len))

    client_hello_body = await reader.read(client_hello_len)
    sni = extract_sni_info(client_hello_body)
    logging.debug('SNI Info is {}'.format(sni))

    log_message = ''
    if not sni or sni not in backend_map:
        log_message = 'Refused'
        refuse_request(writer)
        writer.close()
    else:
        log_message = 'Allow'
        # open connection
        server_host, server_port = get_backend_info(sni)
        logging.debug('Attmpt connect to {}:{}'.format(server_host, server_port))
 
        time_before_req = time.time()
        logging.debug('Time usage before real request: {} millisecs'.format((time_before_req - time_start) * 1000))
 
        server_conn = await asyncio.open_connection(server_host, server_port)
        # rewrite client hello to server
        server_conn[1].write(client_hello_header)
        server_conn[1].write(client_hello_body)

        logging.debug('Time for open_connection and send client hello: {} millisecs'.format((time.time() - time_before_req) * 1000))

        # dial between client and server
        asyncio.ensure_future(dial((reader, writer), server_conn))

    logging.info('Accepted connection from {}, attmpt connect to "{}": {}'.format(peername, sni, log_message))


def start_sniproxy_server(bind_addr='127.0.0.1', bind_port=8443):
    """create a sniproxy server and start it"""
    loop = asyncio.get_event_loop()
    server = asyncio.start_server(handle_tls_connection, host=bind_addr, port=bind_port)
    # press Ctrl+c to stop
    try:
        server = loop.run_until_complete(server)
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.close()
        loop.close()


if __name__ == '__main__':
    start_sniproxy_server(bind_addr='127.0.0.1', bind_port=443)
