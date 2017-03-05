JAVA的加密算法主要是分成四类：MD5加密，SHA加密，HMAC加密，BASE加密，
MD5加密主要是应用于用户名密码的加密，用户登录时使用。
具体代码：
package com.cn.单向加密;
import java.math.BigInteger;
import java.security.MessageDigest;
/*
MD(Message Digest algorithm ，信息摘要算法)
public class MD {
  public static final String KEY_MD = "MD"; 
  public static String getResult(String inputStr)
  {
    System.out.println("=======加密前的数据:"+inputStr);
    BigInteger bigInteger=null;
    try {
     MessageDigest md = MessageDigest.getInstance(KEY_MD); 
     byte[] inputData = inputStr.getBytes();
     md.update(inputData); 
     bigInteger = new BigInteger(md.digest()); 
    } catch (Exception e) {e.printStackTrace();}
    System.out.println("MD加密后:" + bigInteger.toString()); 
    return bigInteger.toString();
  }
  public static void main(String args[])
  {
    try {
       String inputStr = "简单加密"; 
       getResult(inputStr);
    } catch (Exception e) {
      e.printStackTrace();
    }
  }
}
SHA加密
主要用于数字签名标准，是一个将一段明文用不可逆的方式转换成密文的过程。
具体代码：
package com.cn.单向加密;
import java.math.BigInteger;
import java.security.MessageDigest;
public class SHA {
   public static final String KEY_SHA = "SHA"; 
  public static String getResult(String inputStr)
  {
    BigInteger sha =null;
    System.out.println("=======加密前的数据:"+inputStr);
    byte[] inputData = inputStr.getBytes(); 
    try {
       MessageDigest messageDigest = MessageDigest.getInstance(KEY_SHA); 
       messageDigest.update(inputData);
       sha = new BigInteger(messageDigest.digest()); 
       System.out.println("SHA加密后:" + sha.toString()); 
    } catch (Exception e) {e.printStackTrace();}
    return sha.toString();
  }
  public static void main(String args[])
  {
    try {
       String inputStr = "简单加密"; 
       getResult(inputStr);
    } catch (Exception e) {
      e.printStackTrace();
    }
  }
}
HMAC加密
散列消息鉴别码，基于密钥的Hash算法的认证协议。原理主要是，用公开函数和密钥产生一个固定长度的值作为认证标识，用于鉴别消息的完整性。使用一个密钥生成一个固定大小的小数据块，即MAC，并将其加入到消息中，然后传输。接收方利用与发送方共享的密钥进行鉴别认证等
具体代码：
package com.cn.单向加密;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import com.cn.comm.Tools;
/** 
 * 基础加密组件 
 */ 
public abstract class HMAC { 
  public static final String KEY_MAC = "HmacMD"; 
  /** 
   * 初始化HMAC密钥 
   * 
   * @return 
   * @throws Exception 
   */ 
  public static String initMacKey() throws Exception { 
    KeyGenerator keyGenerator = KeyGenerator.getInstance(KEY_MAC); 
    SecretKey secretKey = keyGenerator.generateKey(); 
    return BASE.encryptBASE(secretKey.getEncoded()); 
  } 
  /** 
   * HMAC加密 ：主要方法
   * 
   * @param data 
   * @param key 
   * @return 
   * @throws Exception 
   */ 
  public static String encryptHMAC(byte[] data, String key) throws Exception { 
    SecretKey secretKey = new SecretKeySpec(BASE.decryptBASE(key), KEY_MAC); 
    Mac mac = Mac.getInstance(secretKey.getAlgorithm()); 
    mac.init(secretKey); 
    return new String(mac.doFinal(data)); 
  } 
  public static String getResult(String inputStr)
  {
    String path=Tools.getClassPath();
    String fileSource=path+"/file/HMAC_key.txt";
    System.out.println("=======加密前的数据:"+inputStr);
    String result=null;
    try {
      byte[] inputData = inputStr.getBytes();
      String key = HMAC.initMacKey(); /*产生密钥*/ 
      System.out.println("Mac密钥:===" + key); 
      /*将密钥写文件*/
      Tools.WriteMyFile(fileSource,key);
      result= HMAC.encryptHMAC(inputData, key);
      System.out.println("HMAC加密后:===" + result);
    } catch (Exception e) {e.printStackTrace();} 
    return result.toString();
  }
  public static String getResult(String inputStr)
  {
    System.out.println("=======加密前的数据:"+inputStr);
     String path=Tools.getClassPath();
     String fileSource=path+"/file/HMAC_key.txt";
     String key=null;;
    try {
       /*将密钥从文件中读取*/
       key=Tools.ReadMyFile(fileSource);
       System.out.println("getResult密钥:===" + key); 
    } catch (Exception e) {
      e.printStackTrace();}
    String result=null;
    try {
      byte[] inputData = inputStr.getBytes(); 
      /*对数据进行加密*/
      result= HMAC.encryptHMAC(inputData, key);
      System.out.println("HMAC加密后:===" + result);
    } catch (Exception e) {e.printStackTrace();} 
    return result.toString();
  }
  public static void main(String args[])
  {
    try {
       String inputStr = "简单加密";
       /*使用同一密钥：对数据进行加密：查看两次加密的结果是否一样*/
       getResult(inputStr);
       getResult(inputStr);
    } catch (Exception e) {
      e.printStackTrace();
    }
  }
}
BASE加密
BASE主要用于邮件、证书文件，密钥，http加密，截取http信息等加密。 BASE是一种编码格式， Base传送编码被设计用来把任意序列的位字节描述为一种不易被人直接识别的形式。BASE加密后产生的字节位数是的倍数，如果不够位数以=符号填充。
package com.cn.单向加密;
import sun.misc.BASEDecoder;
import sun.misc.BASEEncoder;
public class BASE {
  /** 
   * BASE解密 
   * 
   * @param key 
   * @return 
   * @throws Exception 
   */ 
  public static byte[] decryptBASE(String key) throws Exception { 
    return (new BASEDecoder()).decodeBuffer(key); 
  } 
  /** 
   * BASE加密 
   * 
   * @param key 
   * @return 
   * @throws Exception 
   */
  public static String encryptBASE(byte[] key) throws Exception { 
    return (new BASEEncoder()).encodeBuffer(key); 
  } 
  public static void main(String[] args) {
   String str="";
    try {
    String result= BASE.encryptBASE(str.getBytes());
     System.out.println("result=====加密数据=========="+result);
     byte result[]= BASE.decryptBASE(result);
     String str=new String(result);
     System.out.println("str========解密数据========"+str);
  } catch (Exception e) {
    e.printStackTrace();
  }
  }
}
