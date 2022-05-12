package encryption;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;




public class SHA_256 {
   
   public static void main(String[] args) throws NoSuchAlgorithmException {
      
      
      String raw = "HI";
      String hex = "";
      
      SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
      byte[] bytes = new byte[16];
      
      random.nextBytes(bytes);
      
      //SALT 생성
      String salt = new String(Base64.getEncoder().encode(bytes));
      String rawAndSalt = raw + salt;
      
      
      
      System.out.println("raw : " + raw);
      System.out.println("salt : " + salt);
   
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      
      /** 평문 암호화
       *  256비트 구성 , 64자리의 문자열 반환
       */
      md.update(raw.getBytes());
      hex = String.format("%064x", new BigInteger(1, md.digest()));
      System.out.println("raw의 헤시값: " + hex );
      
      //평문 + salt(랜덤문자) 암호화
      md.update(rawAndSalt.getBytes());
      hex = String.format("%064x", new BigInteger(1, md.digest()));
      System.out.println("raw + salt 해시값 : " + hex);
      
   }
   
}