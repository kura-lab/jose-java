package net.kuralab.codec;

/**
 * Base64 encode/decode class
 * @author kura
 * @see http://ja.wikipedia.org/wiki/Base64
 *
 */
public class Base64 {
	
	private static final String[] BASE64_TABLE = { "A", "B", "C", "D", "E",
			"F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R",
			"S", "T", "U", "V", "W", "X", "Y", "Z", "a", "b", "c", "d", "e",
			"f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r",
			"s", "t", "u", "v", "w", "x", "y", "z", "0", "1", "2", "3", "4",
			"5", "6", "7", "8", "9", "+", "/" };
	
	/**
	 * Base64 encode
	 * @param binary binary data of bytes array
	 * @return Base64 encoded string
	 */
	public static String encode(byte[] binary) {
		
		StringBuffer buffer = new StringBuffer();
		for (byte b: binary) {
			int s = (int)b;
			if (s < 0) s += 256;
			String hex = Integer.toHexString(s);
			String bitPart1 = Integer.toBinaryString(Integer.parseInt(hex.substring(0, 1), 16));
			String bitPart2 = Integer.toBinaryString(Integer.parseInt(hex.substring(1, 2), 16));
			int bitPart1Padding = 4 - bitPart1.length();
			for (int i = 0; i < bitPart1Padding; i++) {
				bitPart1 = "0" + bitPart1;
			}
			int bitPart2Padding = 4 - bitPart2.length();
			for (int i = 0; i < bitPart2Padding; i++) {
				bitPart2 = "0" + bitPart2;
			}
			buffer.append(bitPart1 + bitPart2);
		}
		
		int bitsPadding = 6 - buffer.length() % 6;
		for (int i = 0; i < bitsPadding; i++) {
			buffer.append("0");
		}
		
		StringBuffer result = new StringBuffer();
		for (int i = 0; i < buffer.length() / 6; i++) {
			result.append(BASE64_TABLE[Integer.parseInt(buffer.substring(i * 6, (i+1) * 6), 2)]);
		}
		int resultPadding = 4 - result.length() % 4;
		for (int i = 0; i < resultPadding; i++) {
			result.append("=");
		}
		
		return result.toString();
	}
	
	/**
	 * Base64 decode
	 * @param data string
	 * @return Base64 decoded binary data of bytes array
	 */
	public static byte[] decode(String data) {
		
		StringBuffer buffer = new StringBuffer();
		for (char c: data.toCharArray()) {
			for (int index = 0; index < BASE64_TABLE.length; index++) {
				if (BASE64_TABLE[index].equals(String.valueOf(c))) {
					String bit = Integer.toBinaryString(index);
					int bitPadding = 6 - bit.length();
					for (int i = 0; i < bitPadding; i++) {
						bit = "0" + bit;
					}
					buffer.append(bit);
				}
			}
		}
		
		byte[] result = new byte[buffer.length() / 8];
		for (int i = 0; i < buffer.length() / 8; i++) {
			String bits = buffer.substring(i * 8, (i + 1) * 8);
			String hexPart1 = String.valueOf(Integer.toHexString(Integer.parseInt(bits.substring(0, 4), 2)));
			String hexPart2 = String.valueOf(Integer.toHexString(Integer.parseInt(bits.substring(4, 8), 2)));
			result[i] = (byte) Integer.parseInt(hexPart1 + hexPart2, 16);
		}
		
		return result;
	}

}
