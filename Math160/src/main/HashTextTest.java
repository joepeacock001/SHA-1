package main;
 
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
 
public class HashTextTest {
 
    /**
     * @param args
     * @throws NoSuchAlgorithmException 
     */
    public static void main(String[] args) throws NoSuchAlgorithmException {
        System.out.println(sha1("DICKS"));
    }
     
    static String sha1(String input) throws NoSuchAlgorithmException {
        MessageDigest mDigest = MessageDigest.getInstance("SHA1");
        byte[] result = mDigest.digest(input.getBytes());
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < result.length; i++) {
            sb.append(Integer.toString((result[i] & 0xff) + 0x100, 16).substring(1));
            
        }
         
        return sb.toString();
    }
    //2bfd06ab0cbb7b2298badcfe8a9763d656252620
    //c21b8bae9614dd453dba0829956cf3822add7d69

   
}

/*
73
32
97
109
32
97
110
103
114
121
512
*/