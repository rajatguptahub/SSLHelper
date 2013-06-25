package prj.cyclops;

import java.nio.ByteBuffer;

public class VariableCapacityByteBuffer {
    private ByteBuffer buffer;

    public VariableCapacityByteBuffer(ByteBuffer buffer) {
        this.buffer = buffer;
    }

    public ByteBuffer getBuffer() {
        return buffer;
    }

    public void put(byte[] data) {
        if (buffer.remaining() < data.length) {
            ByteBuffer temp = ByteBuffer.allocate(buffer.capacity() + (data.length - buffer.remaining()));
            temp.put(buffer);
            buffer = temp;
        }
        buffer.put(data);
    }
}
