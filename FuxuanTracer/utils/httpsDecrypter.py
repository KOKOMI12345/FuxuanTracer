from FuxuanTracer.utils.logger import logger
from FuxuanTracer.dependecy.needModules import crypto , SSL , WantReadError , time , socket

KEYPATH = r"FuxuanTracer\key\server.key"
CERTPATH = r"FuxuanTracer\key\server.crt"

class HTTPsDecrypter:
    def __init__(self, 
        key_path: str, 
        cert_path: str,
    ):
        if not key_path or not cert_path:
            raise Exception("key_path and cert_path must be set")
        
        self.key_path = key_path
        self.cert_path = cert_path
        self.ssl_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.encrypted_data = None
        self.dercypted_data = []

        # 设置 TLS 版本为 TLS 1.2
        self.sslContext = SSL.Context(SSL.TLSv1_2_METHOD)
        
        # 初始化 SSL 连接上下文
        self.InitSSL()

    def setEncrpytedData(self, data: bytes) -> "HTTPsDecrypter":
        if not data:
            raise Exception("data must be set")
        self.encrypted_data = data
        return self

    def InitSSL(self) -> None:
        try:
            # 加载证书和私钥
            logger.info("Loading certificate and private key...")
            self.sslContext.use_certificate_file(self.cert_path)
            self.sslContext.use_privatekey_file(self.key_path)
            logger.info("Certificate and private key loaded")
        except Exception as e:
            logger.error(f"Failed to load certificate or private key: {e}")
            raise

    def decrypt(self,host: str,port=443) -> None:
        # 创建 SSL 连接对象
        logger.info(f"Connecting to {host}:{port}...")
        self.ssl_sock.connect((host, port))
        ssl_conn = SSL.Connection(self.sslContext, self.ssl_sock)
        
        while True:
            try:
                decrypted_data = ssl_conn.bio_read(4096)
                if not decrypted_data:
                    break
                self.dercypted_data.append(decrypted_data)
            except WantReadError:
                # 如果出现 WantReadError，等待一段时间再尝试读取
                time.sleep(0.1)  # 等待0.1秒

    def getResult(self) -> bytes:
        return b"".join(self.dercypted_data)