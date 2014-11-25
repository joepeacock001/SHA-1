package main;

import java.nio.ByteBuffer;
import java.util.Scanner;

/**
 * 
 * This is my custom implementation of the cryptographic hash function SHA-1 on a String.
 * 
 * The ideas in this program are modified from a lecture on youtube given by Christof Paar,
 * as well as the ideas found in the FIPS publication.  
 * 
 * @author Joe Peacock
 * @Version 1.2
 * @Date 11/22/14
 * 
 * 
 *
 */
public class SHA1 {
	//the message to be hashed
	private static String message = "Default Message Value";
	//the initial input into the algorithm
	private static int A = 0x67452301;
	private static int B = 0xEFCDAB89;
	private static int C = 0x98BADCFE;
	private static int D = 0x10325476;
	private static int E = 0xC3D2E1F0;
	//Constants, one for each stage
	private static final int k1 = 0x5A827999;
	private static final int k2 = 0x6ED9EBA1;
	private static final int k3 = 0x8F1BBCDC;
	private static final int k4 = 0xCA62C1D6;

	/**
	 * This is the main method, which sets up the algorithm, and controls the calls to all other methods
	 * 
	 * @param args
	 * 		Not used
	 */
	public static void main(String[] args) {
		Scanner keys = new Scanner(System.in);
		message=keys.nextLine();
		byte[] tempM = message.getBytes();
		byte[] message = preProcessing(tempM);
		int len = message.length * 8;
		int numBlocks = len / 512;
		int[] ini = new int[5]; //initial inputs.  Stored in an array for convenience
		ini[0] = A;
		ini[1] = B;
		ini[2] = C;
		ini[3] = D;
		ini[4] = E;
		byte[] block = new byte[64]; //calls oneBlock for each block of input
		for (int i = 0; i < numBlocks; i++) {
			for (int j = 0; j < 64; j++) {
				block[j] = message[64 * i + j];
			}
			ini = oneBlock(block, ini);
		}
		byte[] result = new byte[20]; 
		byte[] t = new byte[4];
		for (int i = 0; i < 5; i++) { //takes the new values for  A, B, C, D, and E, and turns them into a byte array
			t = ByteBuffer.allocate(4).putInt(ini[i]).array();
			for (int j = 0; j < 4; j++) {
				result[i * 4 + j] = t[j];
			}
		}
		StringBuffer sb = new StringBuffer();  //takes the result and turns it into hex characters for output
		for (int i = 0; i < result.length; i++) {
			sb.append(Integer.toString((result[i] & 0xff) + 0x100, 16)
					.substring(1));

		}

		System.out.println(sb.toString());
		keys.close();
	}

	/**
	 * 
	 * Handles the compression function for one block of input. 
	 * 
	 * @param block
	 * 		The block that we running through the compression function
	 * @param input
	 * 		The array of A, B, C, d and E- the input conditions for the round function
	 * @return
	 */
	public static int[] oneBlock(byte[] block, int[] input) {
		int[] currOut = new int[5];
		for (int i = 0; i < 80; i++) {
			currOut = oneIteration(input, i, scheduler(block, i));
			for (int j = 0; j < 5; j++) {
				input[j] = weirdAdd(input[j], currOut[j]);
			}
			

		}
		return input;
	}
	
	/**
	 * This handles each iteration of the round function.
	 * 
	 * @param input
	 * 		A, B, C, D, and E
	 * @param stage
	 * 		The stage the round function is in.  Different stages mean different constants and functions are used
	 * @param schedule
	 * 		The value of the message scheduler for this round
	 * @return
	 */
	public static int[] oneIteration(int[] input, int stage, int schedule) {
		int[] output = new int[5];
		output[1] = input[0];
		output[3] = input[2];
		output[2] = input[1] << 30;
		output[4] = input[3];
		int newE = 0;
		if (stage == 1) {
			newE = weirdAdd(input[4], f1(input[1], input[2], input[3]));
			newE = weirdAdd(newE, input[0] << 5);
			newE = weirdAdd(schedule, newE);
			newE = weirdAdd(newE, k1);
		}
		if (stage == 2) {
			newE = weirdAdd(input[4], f2(input[1], input[2], input[3]));
			newE = weirdAdd(newE, input[0] << 5);
			newE = weirdAdd(schedule, newE);
			newE = weirdAdd(newE, k2);
		}
		if (stage == 3) {
			newE = weirdAdd(input[4], f3(input[1], input[2], input[3]));
			newE = weirdAdd(newE, input[0] << 5);
			newE = weirdAdd(schedule, newE);
			newE = weirdAdd(newE, k3);
		}
		if (stage == 4) {
			newE = weirdAdd(input[4], f4(input[1], input[2], input[3]));
			newE = weirdAdd(newE, input[0] << 5);
			newE = weirdAdd(schedule, newE);
			newE = weirdAdd(newE, k4);
		}
		output[0] = newE;
		return output;
	}
	
	/**
	 * Adds two numbers modulo 2^32
	 * 
	 * @param in1
	 * 		One of the numbers to add
	 * @param in2
	 * 		The other number
	 * @return
	 * 		The sum, modulo 2^32
	 */
	public static int weirdAdd(int in1, int in2) {
		long sum = (long) in1 + (long) in2;
		if (sum < Math.pow(2.0, 32.0))
			return (int) sum;
		else
			return (int) (sum - Math.pow(2.0, 32.0));
	}

	/**
	 * Transforms an array of bytes into its integer representation
	 * Only works on an array of size 4, that is okay because that is the only case
	 * in which I call it.
	 * 
	 * This method was slightly modified from  tutorial on Java2s.com
	 * 
	 * @param bytes
	 * 		An array of bytes of length 4
	 * @return
	 * 		The integer representation of the 32 bits in the byte array
	 */
	public static int toInt(byte[] bytes) {
		int result = 0;
		for (int i = 0; i < 4; i++) {
			result = (result << 8) - Byte.MIN_VALUE + (int) bytes[i];
		}
		return result;
	}
	
	/**
	 * takes the input of one block, and outputs a unique integer for each of the 80 rounds
	 * 
	 * @param block
	 * 		The block of input
	 * @param rep
	 * 		The repetition of the round function
	 * @return
	 */
	public static int scheduler(byte[] block, int rep) {
		byte[] toRet = new byte[4];
		if (rep < 16) {
			for (int i = rep * 4; i < rep * 4 + 4; i++) {
				toRet[i - rep * 4] = block[i];
			}
			return toInt(toRet);
		} else {
			return (scheduler(block, rep - 16) ^ scheduler(block, rep - 14)
					^ scheduler(block, rep - 8) ^ scheduler(block, rep - 3)) << 1;

		}

	}

	/**
	 * Handles the preprocessing of the input.  Adds any padding that is necessary and stors it in a byte array.
	 * 
	 * @param in
	 * 		The byte array of the original message
	 * @return
	 * 		The new, padded byte array of length%512=0
	 */
	public static byte[] preProcessing(byte[] in) {
		int newLen = (64 - in.length % 64) + in.length;
		byte[] message = new byte[newLen];
		int len = message.length * 8;
		if (in.length % 64 != 0) {
			byte[] tB = ByteBuffer.allocate(8).putInt(len).array();
			for (int i = 0; i < len / 8; i++) {
				if (i < in.length)
					message[i] = in[i];
				else if (i == in.length)
					message[i] = (byte) 0x80;
				else if (i > in.length && (len / 8) - i > 8)
					message[i] = (byte) 0x00;
				else {
					message[i] = tB[(len / 8) - i - 1];
				}

			}
			long temp = (long) len;
			byte[] tmp = new byte[8];
			ByteBuffer buf = ByteBuffer.wrap(tmp);
			buf.putLong(temp);
			for (int i = len / 8 - 1; i > -1; i--) {
				if ((8 - (len / 8) - i - 1) >= 0)
					message[i] = tmp[(8 - (len / 8) - i - 1)];
				else
					break;
			}
		}
		return message;
	}

	/**
	 * Prints a byte array- used only for testing
	 * 
	 * @param toPrint
	 * 		The array which will be printed
	 */
	public static void print(byte[] toPrint) {
		for (int i = 0; i < toPrint.length; i++) {
			System.out.println(toPrint[i]);
		}
	}

	/**
	 * Handles the function of B, C, and D for the first stage of rounds
	 * 
	 * @param b
	 * 		the value of B from the round function
	 * @param c
	 * 		the value of C from the round function
	 * @param d
	 * 		the value of D from the round function
	 * @return
	 * 		The output of the function
	 */
	public static int f1(int b, int c, int d) {
		return ((b & c) | ((~b) & d));
	}
	/**
	 * Handles the function of B, C, and D for the second stage of rounds
	 * 
	 * @param b
	 * 		the value of B from the round function
	 * @param c
	 * 		the value of C from the round function
	 * @param d
	 * 		the value of D from the round function
	 * @return
	 * 		The output of the function
	 */
	public static int f2(int b, int c, int d) {
		return (b ^ c ^ d);
	}
	/**
	 * Handles the function of B, C, and D for the third stage of rounds
	 * 
	 * @param b
	 * 		the value of B from the round function
	 * @param c
	 * 		the value of C from the round function
	 * @param d
	 * 		the value of D from the round function
	 * @return
	 * 		The output of the function
	 */
	public static int f3(int b, int c, int d) {
		return ((b & c) | (b & d) | (c & d));
	}
	/**
	 * Handles the function of B, C, and D for the first fourth of rounds
	 * 
	 * @param b
	 * 		the value of B from the round function
	 * @param c
	 * 		the value of C from the round function
	 * @param d
	 * 		the value of D from the round function
	 * @return
	 * 		The output of the function
	 */
	public static int f4(int b, int c, int d) {
		return (b ^ c ^ d);
	}

}
