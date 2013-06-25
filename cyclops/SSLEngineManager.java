package prj.cyclops;

import javax.net.ssl.*;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;

public class SSLEngineManager {
    private SSLEngine engine;
    private HandshakeCompletedListener handshakeCompletedListener;
    private OnNetworkDataReadyListener onNetworkDataReadyListener;
    private OnApplicationDataReadyListener onApplicationDataReadyListener;
    private byte[] remainingData;
    private boolean isHandshakeComplete;

    public SSLEngineManager(SSLContext sslContext, boolean clientMode) {
        engine = sslContext.createSSLEngine();
        engine.setUseClientMode(clientMode);
        engine.setNeedClientAuth(false);

        remainingData = new byte[0];
        isHandshakeComplete = false;
    }

    public void setHandshakeCompletedListener(HandshakeCompletedListener listener) {
        handshakeCompletedListener = listener;
    }

    public void setOnNetworkDataReadyListener(OnNetworkDataReadyListener listener) {
        onNetworkDataReadyListener = listener;
    }

    public void setOnApplicationDataReadyListener(OnApplicationDataReadyListener listener) {
        onApplicationDataReadyListener = listener;
    }

    public boolean isHandshakeComplete() {
        return isHandshakeComplete;
    }

    public void startHandshake() throws IOException {
        engine.beginHandshake();
        shakeHands();
    }

    public void shakeHands() throws IOException {
        while (true) {
            switch (engine.getHandshakeStatus()) {
                case FINISHED:
                    onHandshakeFinished();
                    return;
                case NOT_HANDSHAKING:
                    return;
                case NEED_TASK:
                    runDelegatedTasks();
                    break;
                case NEED_WRAP:
                    wrapData(new byte[0]);
                    break;
                case NEED_UNWRAP:
                    if (remainingData.length > 0) {
                        unwrapData(new byte[0]);
                    }
                    break;
            }
        }
    }

    public void wrapData(byte[] data) throws IOException {
        VariableCapacityByteBuffer networkDataToBeSent = new VariableCapacityByteBuffer(
                ByteBuffer.allocate(engine.getSession().getPacketBufferSize())
        );

        ByteBuffer temp = ByteBuffer.allocate(engine.getSession().getPacketBufferSize());
        SSLEngineResult result;
        int totalBytesConsumed = 0;
        do {
            result = engine.wrap(ByteBuffer.wrap(Arrays.copyOfRange(data, totalBytesConsumed, data.length)), temp);
            networkDataToBeSent.put(temp.array());
            temp.clear();
            totalBytesConsumed = totalBytesConsumed + result.bytesConsumed();
        } while (result.getStatus().equals(SSLEngineResult.Status.OK) &&
                totalBytesConsumed < data.length &&
                result.bytesProduced() > 0);

        ByteBuffer dataToBeSent = networkDataToBeSent.getBuffer();
        dataToBeSent.flip();
        onNetworkDataReadyListener.onNetworkDataReady(getBytesFromBuffer(dataToBeSent, dataToBeSent.limit()));
    }

    public void unwrapData(byte[] data) throws IOException {
        ByteBuffer outputBuffer = ByteBuffer.allocate(engine.getSession().getApplicationBufferSize());
        ByteBuffer inputBuffer = ByteBuffer.allocate(data.length + remainingData.length);
        if (remainingData.length > 0) {
            inputBuffer.put(remainingData);
            remainingData = new byte[0];
        }
        if (data.length > 0) {
            inputBuffer.put(data);
        }
        inputBuffer.flip();

        SSLEngineResult result;
        int bytesConsumed = 0;
        do {
            result = engine.unwrap(inputBuffer, outputBuffer);
            bytesConsumed = bytesConsumed + result.bytesConsumed();
        } while (needsUnwrap(result, bytesConsumed, inputBuffer.array().length));

        remainingData = Arrays.copyOfRange(inputBuffer.array(), inputBuffer.position(), inputBuffer.limit());

        if (result.getHandshakeStatus().equals(SSLEngineResult.HandshakeStatus.FINISHED)) {
            onHandshakeFinished();
        }

        onApplicationDataReadyListener.onApplicationDataReady(Arrays.copyOfRange(outputBuffer.array(), 0, outputBuffer.position()));
    }

    public void close() {
        try {
            engine.closeOutbound();
            engine.closeInbound();
        } catch (IOException ignored) {
        }
    }

    private boolean needsUnwrap(SSLEngineResult result, int totalBytesConsumed, int totalBytesToBeConsumed) {
        if (!isHandshakeComplete) {
            return result.getStatus() == SSLEngineResult.Status.OK &&
                    result.getHandshakeStatus().equals(SSLEngineResult.HandshakeStatus.NEED_UNWRAP) &&
                    result.bytesProduced() == 0;
        } else {
            return result.getStatus() == SSLEngineResult.Status.OK &&
                    (result.bytesProduced() != 0 || totalBytesConsumed < totalBytesToBeConsumed);
        }
    }

    private void onHandshakeFinished() {
        isHandshakeComplete = true;
        handshakeCompletedListener.handshakeCompleted(null);
        handshakeCompletedListener = null;
    }

    private void runDelegatedTasks() {
        Runnable task;
        while ((task = engine.getDelegatedTask()) != null) {
            task.run();
        }
    }

    private byte[] getBytesFromBuffer(ByteBuffer buffer, int numberOfBytes) {
        byte[] bytes = new byte[numberOfBytes];
        buffer.get(bytes, 0, numberOfBytes);
        return bytes;
    }
}
