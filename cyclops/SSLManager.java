package prj.cyclops;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;

public class SSLManager<KEY> {
    private Map<KEY, SSLEngineManager> engines;
    private SSLContext context;
    private boolean clientMode;

    public SSLManager(boolean clientMode) throws IOException, KeyStoreException, NoSuchAlgorithmException,
            CertificateException, UnrecoverableKeyException, KeyManagementException {
        engines = new HashMap<>();
        this.clientMode = clientMode;
        context = createSSLContext();
    }

    public void createEngine(KEY socket) {
        engines.put(socket, new SSLEngineManager(context, clientMode));
    }

    public void setHandshakeCompletedListener(KEY socket, HandshakeCompletedListener listener) {
        engines.get(socket).setHandshakeCompletedListener(listener);
    }

    public void setOnNetworkDataReadyListener(KEY socket, OnNetworkDataReadyListener listener) {
        engines.get(socket).setOnNetworkDataReadyListener(listener);
    }

    public void setOnApplicationDataReadyListener(KEY socket, OnApplicationDataReadyListener listener) {
        engines.get(socket).setOnApplicationDataReadyListener(listener);
    }

    public boolean isHandshakeComplete(KEY socket) {
        return engines.get(socket).isHandshakeComplete();
    }

    public void startHandshake(KEY socket) throws IOException {
        engines.get(socket).startHandshake();
    }

    public void shakeHands(KEY socket) throws IOException {
        engines.get(socket).shakeHands();
    }

    public void wrapData(KEY socket, byte[] data) throws IOException {
        engines.get(socket).wrapData(data);
    }

    public void unwrapData(KEY socket, byte[] data) throws IOException {
        engines.get(socket).unwrapData(data);
    }

    public void closeEngine(KEY socket) {
        engines.get(socket).close();
        engines.remove(socket);
    }

    private SSLContext createSSLContext() throws IOException, KeyStoreException, NoSuchAlgorithmException,
            CertificateException, UnrecoverableKeyException, KeyManagementException {
        char[] password = "android@39".toCharArray();

        KeyStore keyStore = KeyStore.getInstance("JKS");
        FileInputStream stream = new FileInputStream("android-ssc.jks");
        keyStore.load(stream, password);
        stream.close();
        SSLContext sslContext = SSLContext.getInstance("TLS");

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(keyStore);

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, password);
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        return sslContext;
    }
}
