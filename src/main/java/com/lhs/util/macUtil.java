package com.lhs.util;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
/**
 * 
 * 类说明：<br>
 * Mac签名工具类
 * 
 * <p>
 * 详细描述：<br>
 * 
 * 
 * </p>
 * 
 * @author 范 
 * 
 * CreateDate: 2015年9月21日
 */
public class macUtil {
	public static String HASH_ALG_SHA1 = "30";
	public static String HASH_ALG_SHA256 = "31";
	public static String HASH_ALG_SHA512 = "32";
	public static String HASH_ALG_MD5 = "33";
	public static String CHARARRAY = "0123456789ABCDEF";
	public static String Algorithm = "DES";
	
	/**
	 * 
	 * 方法说明：<br>
	 * @param timeStamp 时间戳yyyyMMddHHmmss
	 * @param macKey  密钥
	 * @param hashAlg 算法
	 * @param msg 明文
	 * @return 生成密文
	 */
	public static String genMsgMac(String timeStamp, String macKey,String hashAlg, String msg) {
		String macHexValue = "";
		try {
			byte[] signKey = DesEncrypt(Hex2bytes(macKey), Hex2bytes(timeStamp + "80"));
			byte[] signSrc = calcHash(msg, hashAlg);
			String signSrcHex = bytes2Hex(signSrc) + "80";
			int paddingLength = 16 - signSrcHex.length() % 16;
			if (paddingLength != 16) {
				paddingLength = paddingLength / 2;
				StringBuffer sb = new StringBuffer(signSrcHex);
				for (int i = 0; i < paddingLength; i++) {
					sb.append("00");
				}
				signSrcHex = sb.toString();
			}
			signSrc = Hex2bytes(signSrcHex);
			macHexValue = bytes2Hex(DesEncrypt(signKey, signSrc));
		} catch (Exception e) {
			e.printStackTrace();
		}
		return macHexValue;
	}
	
	/**
	 * 
	 * 方法说明：<br>
	 * 	MAC校验
	 * @param timeStamp 时间戳yyyyMMddHHmmss
	 * @param macKey  密钥
	 * @param hashAlg 算法
	 * @param msg	明文
	 * @param msgMac 密文
	 * @return true 成功,false失败
	 */
	public static boolean verifyMsgMac(String timeStamp, String macKey,String hashAlg, String msg, String msgMac) {
		String macValue = genMsgMac(timeStamp, macKey, hashAlg, msg);
//		System.err.println(macValue);
		if (macValue.compareTo(msgMac) == 0) {
			return true;
		}
		return false;
	}
	
	/**
	 * 
	 * 方法说明：<br>
	 * 
	 * @param keybyte
	 * @param src
	 * @return
	 */
	private static byte[] DesEncrypt(byte[] keybyte, byte[] src) {
		SecureRandom sr = new SecureRandom();
		byte[] result = null;
		// 从原始密钥数据创建DESKeySpec对象
		Cipher cipher = null ;
		try {
			DESKeySpec dks = new DESKeySpec(keybyte);
			// 创建一个密钥工厂，然后用它把DESKeySpec转换成SecretKey对象
			SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(Algorithm);
			SecretKey securekey = keyFactory.generateSecret(dks);
			// Cipher对象实际完成加密操作
			cipher = Cipher.getInstance(Algorithm);
			// 用密钥初始化Cipher对象
			cipher.init(Cipher.ENCRYPT_MODE, securekey, sr);
			result = cipher.doFinal(src);
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
		return result;

	}

	private static byte[] calcHash(String msg, String hashAlg) {
		String encName = "MD5";
		if (hashAlg == null) {
		} else if (hashAlg.compareTo(HASH_ALG_SHA1) == 0) {
			encName = "SHA-1";
		} else if (hashAlg.compareTo(HASH_ALG_SHA256) == 0) {
			encName = "SHA-256";
		} else if (hashAlg.compareTo(HASH_ALG_SHA512) == 0) {
			encName = "SHA-512";
		} else if (hashAlg.compareTo(HASH_ALG_MD5) == 0) {
			encName = "MD5";
		}
		return HashEncrypt(msg, encName);
	}

	private static byte[] HashEncrypt(String strSrc, String encName) {
		MessageDigest md = null;
		byte[] bt = strSrc.getBytes();
		try {
			if (encName == null || encName.equals("")) {
				encName = "MD5";
			}
			md = MessageDigest.getInstance(encName);
			md.update(bt);
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Invalid algorithm.");
			return null;
		}
		return md.digest();
	}

	private static byte[] Hex2bytes(String hexString) throws Exception {
		if (hexString.length() % 2 != 0) {
			Exception c = new ArrayIndexOutOfBoundsException();
			throw c;
		}
		String src = hexString.toUpperCase();
		int length = src.length();
		byte[] dst = new byte[length / 2];
		char[] hexChars = src.toCharArray();
		for (int i = 0; i < length; i++) {
			if (i % 2 == 0) {
				dst[i / 2] = (byte) (CHARARRAY.indexOf(hexChars[i]));
			} else {
				dst[i / 2] = (byte) ((dst[i / 2]) << 4 | (CHARARRAY.indexOf(hexChars[i])));
			}
		}
		return dst;
	}

	private static String bytes2Hex(byte[] src) {
		StringBuffer dst = new StringBuffer();
		for (int i = 0; i < src.length; i++) {
			int v = src[i] & 0xFF;
			String temp = Integer.toHexString(v);
			if (temp.length() == 2) {
				dst.append(temp);
			} else {
				dst.append("0" + temp);
			}
		}
		return dst.toString().toUpperCase();
	}


	public static void main(String[] args) {
		String strSrc = "可以加密汉字.Oh,and english";
		System.out.println("明文：" + strSrc);

		System.out.println("密文:" + macUtil.genMsgMac("20140111180909", "0123456789ABCDEF", "31", strSrc));
		
		System.out.println("验证结果");
		System.out.println(macUtil.verifyMsgMac("20140111180909", "0123456789ABCDEF", "31", strSrc,
				"E2E90B28A3C789AFF7E015EBC74ACE4059FC2404C9DB4BD4E14399B7E27EDC2894980588BF9DB3DAE36BF8623C16B950"));
	}
}
