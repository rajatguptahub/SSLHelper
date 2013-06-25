package prj.cyclops;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import prj.cyclo.Agent;
import prj.cyclo.SSLTransport;
import prj.cyclo.TCPReactor;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import java.io.IOException;
import java.net.Socket;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

public abstract class SecureAgent extends Agent {
    private static final long HANDSHAKE_TIMEOUT_IN_SECONDS = 60;
    private prj.cyclops.SSLManager<Socket> _sslManager;
    private SSLTransport<Socket> _sslTransport;
    private final Logger _logger = LoggerFactory.getLogger(this.getClass().getSimpleName());
    private final Map<Socket, ScheduledFuture> _handshakeTimeoutTasks = new HashMap<>();

    protected SecureAgent(TCPReactor reactor, ScheduledExecutorService threadPool, prj.cyclops.SSLManager<Socket> sslManager) {
        super(reactor, threadPool);
        setupSSL(sslManager);
    }


    public SecureAgent(TCPReactor reactor, prj.cyclops.SSLManager<Socket> sslManager) {
        super(reactor);
        setupSSL(sslManager);
    }

    private void setupSSL(SSLManager<Socket> sslManager) {
        _sslManager = sslManager;
        _sslTransport = new SSLTransport<Socket>() {

            public void send(Socket socket, byte[] data) throws IOException {
                SecureAgent.super.send(socket, data);
            }
        };
    }

    public abstract void secureConnectionMade(Socket socket);

    public abstract void secureReceive(Socket socket, byte[] incomingData);

    @Override
    public final void connectionMade(final Socket socket) {
        _sslManager.createEngine(socket);
        try {
            final ScheduledFuture handShakeTimeoutTask = scheduleHandshakeTimeout(socket);
            _handshakeTimeoutTasks.put(socket, handShakeTimeoutTask);
            _sslManager.setHandshakeCompletedListener(socket, new HandshakeCompletedListener() {
                public void handshakeCompleted(HandshakeCompletedEvent alwaysNull) {
                    cancelHandshakeTimeoutTask(socket);
                    secureConnectionMade(socket);
                }
            });
            _sslManager.setOnNetworkDataReadyListener(socket, new OnNetworkDataReadyListener() {
                @Override
                public void onNetworkDataReady(byte[] networkDataToBeSent) {
                    try {
                        _sslTransport.send(socket, networkDataToBeSent);
                    } catch (Exception ignored) {
                    }
                }
            });
            _sslManager.startHandshake(socket);
        } catch (Exception e) {
            if (e instanceof IOException) {
                _logger.debug("IOException during SSLHandshake in SecureAgent.connectionMade, closing socket: {}", socket);
            } else {
                _logger.error("Exception during SSLHandshake in SecureAgent.connectionMade, closing socket: ", e);
            }
            close(socket);
        }
    }

    private ScheduledFuture scheduleHandshakeTimeout(final Socket socket) {
        return _agency.schedule(new Runnable() {
            @Override
            public void run() {
                _logger.info("Handshake timed out. Closing socket {}", socket);
                _handshakeTimeoutTasks.remove(socket);
                close(socket);
            }
        }, HANDSHAKE_TIMEOUT_IN_SECONDS, TimeUnit.SECONDS);
    }

    public final void receive(final Socket socket, byte[] incomingData) {
        _sslManager.setOnApplicationDataReadyListener(socket, new OnApplicationDataReadyListener() {
            @Override
            public void onApplicationDataReady(byte[] applicationDataReceived) {
                try {
                    if (_sslManager.isHandshakeComplete(socket)) {
                        secureReceive(socket, applicationDataReceived);
                    } else {
                        _sslManager.setOnNetworkDataReadyListener(socket, new OnNetworkDataReadyListener() {
                            @Override
                            public void onNetworkDataReady(byte[] networkDataToBeSent) {
                                try {
                                    _sslTransport.send(socket, networkDataToBeSent);
                                } catch (Exception ignored) {
                                }
                            }
                        });
                        _sslManager.shakeHands(socket);
                    }
                } catch (Exception e) {
                    if (e instanceof IOException) {
                        _logger.debug("IOException in SecureAgent.receive, closing socket: {}", socket);
                    } else {
                        _logger.error("Exception in SecureAgent.receive, closing socket: ", e);
                    }
                    close(socket);
                }
            }
        });
        try {
            _sslManager.unwrapData(socket, incomingData);
        } catch (Exception e) {
            if (e instanceof IOException) {
                _logger.debug("IOException in SecureAgent.receive, closing socket: {}", socket);
            } else {
                _logger.error("Exception in SecureAgent.receive, closing socket: ", e);
            }
            close(socket);
        }
    }

    public final void secureSend(final Socket socket, byte[] plainData) throws IOException {
        _sslManager.setOnNetworkDataReadyListener(socket, new OnNetworkDataReadyListener() {
            @Override
            public void onNetworkDataReady(byte[] networkDataToBeSent) {
                try {
                    _sslTransport.send(socket, networkDataToBeSent);
                } catch (Exception e) {
                    if (e instanceof IOException) {
                        _logger.info("IOException in secure send: {}", socket);
                    } else {
                        _logger.error("exception in secure send: ", e);
                    }
                }
            }
        });
        try {
            _sslManager.wrapData(socket, plainData);
        } catch (Exception e) {
            if (e instanceof IOException) {
                _logger.info("IOException in secure send: {}", socket);
            } else {
                _logger.error("exception in secure send: ", e);
            }
            throw new IOException(e);
        }
    }

    @Override
    public final void close(Socket socket) {
        cancelHandshakeTimeoutTask(socket);
        _sslManager.closeEngine(socket);
        super.close(socket);
        secureClose(socket);
    }

    @Override
    public void onClose(Socket socket) {
        close(socket);
    }

    public void secureClose(Socket socket) {
        //Extending class should override this
    }

    @Override
    public final void send(Socket socket, byte[] data) throws IOException {
        secureSend(socket, data);
    }

    private void cancelHandshakeTimeoutTask(Socket socket) {
        ScheduledFuture handshakeTimeoutTask = _handshakeTimeoutTasks.remove(socket);
        if (handshakeTimeoutTask != null) {
            handshakeTimeoutTask.cancel(false);
        }
    }

}
