import java.io.File;
import java.nio.ByteBuffer;
import java.io.*;
import java.util.Arrays;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.spec.KeySpec;


/**
 * @author <Hoang Nguyen>
 * @netid <hdn220000>
 * @email <hdn220000@utdallas.edu>
 */
public class EFS extends Utility{


	private static int KEY_LENGTH = 128;
	private static int USER_LENGTH = 128;
	private static int PASS_LENGTH = 32;
	private static int SALT_LENGTH = 16;
	private static int HEADER_LENGTH = USER_LENGTH + PASS_LENGTH + SALT_LENGTH;
	private static int SECRET_LENGTH = 128;
	private static int METADATA_LENGTH = HEADER_LENGTH + SECRET_LENGTH;
	private static int CONTENT_BLOCK_SIZE = 960;
	private static int HMAC_LENGTH = 32;

	public EFS(Editor e)
	{
		super(e);
		set_username_password();
	}

	private static String byteArrayToString(byte[] byteArray) {
		StringBuilder sb = new StringBuilder("[");
		for (byte b : byteArray) {
			sb.append(b).append(", ");
		}
		sb.setLength(sb.length() - 2);
		sb.append("]");
		return sb.toString();
	}

	private static byte[] generateIV(byte[] key, byte[] salt) {
		if (key.length != salt.length) {
			throw new IllegalArgumentException("Arrays must have the same length");
		}

		byte[] iv = new byte[key.length];

		for (int i = 0; i < key.length; i++) {
			iv[i] = (byte) (key[i] ^ salt[i]);
		}

		return iv;
	}

	private static void incrementCounter(byte[] counter) {
		for (int i = 0; i < counter.length; i++) {
			if (++counter[i] != 0) {
				break;
			}
		}
	}

	private byte[] generateKey(String password, byte[] salt, int keyLength) {
		try {
			String paddedPassword = paddingString(password, keyLength);
			int iterations = 10000;

			KeySpec spec = new PBEKeySpec(paddedPassword.toCharArray(), salt, iterations, keyLength);
			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
			byte[] key = factory.generateSecret(spec).getEncoded();

			return key;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}



	private static byte[] encryptAES_CTR(byte[] plaintext, byte[] key, byte[] salt) throws Exception {

		byte[] ciphertext = new byte[plaintext.length];
		byte[] counter = generateIV(key, salt);

		for (int i = 0; i < plaintext.length; i += 16) {
			byte[] encryptedCounter = encript_AES(counter, key);
			for (int j = 0; j < 16 && i + j < plaintext.length; j++) {
				ciphertext[i + j] = (byte) (plaintext[i + j] ^ encryptedCounter[j]);
			}
			incrementCounter(counter);
		}
		return ciphertext;
	}

	private static byte[] decryptAES_CTR(byte[] ciphertext, byte[] key, byte[] salt) throws Exception {

		byte[] plaintext = new byte[ciphertext.length];
		byte[] counter = generateIV(key, salt);


		for (int i = 0; i < ciphertext.length; i += 16) {
			byte[] encryptedCounter = encript_AES(counter, key);
			for (int j = 0; j < 16 && i + j < ciphertext.length; j++) {
				plaintext[i + j] = (byte) (ciphertext[i + j] ^ encryptedCounter[j]);
			}
			incrementCounter(counter);
		}
		return plaintext;
	}

	private static byte[] computeHMAC (byte[] key, byte[] message) throws Exception{

		// Pad the key if needed
		int blockSize = 32; // 32 bytes block size for SHA-256 
		if (key.length < blockSize) {
			key = Arrays.copyOf(key, blockSize);
		}

		// Construct the ipad and opad values
		byte[] ipadKey = new byte[blockSize];
		byte[] opadKey = new byte[blockSize];
		for (int i = 0; i < blockSize; i++) {
			ipadKey[i] = (byte) (0x36 ^ key[i]);
			opadKey[i] = (byte) (0x5C ^ key[i]);
		}

		// Concatenate inner hash input
		byte[] innerHashInput = new byte[blockSize + message.length];
		System.arraycopy(ipadKey, 0, innerHashInput, 0, blockSize);
		System.arraycopy(message, 0, innerHashInput, blockSize, message.length);

		// Perform inner hash calculation
		byte[] innerHashOutput = hash_SHA256(innerHashInput);

		// Concatenate outer hash input
		byte[] outerHashInput = new byte[blockSize + innerHashOutput.length];
		System.arraycopy(opadKey, 0, outerHashInput, 0, blockSize);
		System.arraycopy(innerHashOutput, 0, outerHashInput, blockSize, innerHashOutput.length);

		// Perform outer hash calculation
		return hash_SHA256(outerHashInput);
	}




	private static String paddingString(String string, int desiredLength) {
		if (string.length() >= desiredLength) {
			return string; 
		} else {
			StringBuilder paddedString = new StringBuilder(string);
			while (paddedString.length() < desiredLength) {
				paddedString.append("\0"); // Pad with spaces
			}
			return paddedString.toString();
		}
	}

	private byte[] padWithPKCS7(byte[] data, int blockSize) {
		int paddingLength = blockSize - (data.length % blockSize);
		byte paddingByte = (byte) paddingLength;
		byte[] paddedData = Arrays.copyOf(data, data.length + paddingLength);
		Arrays.fill(paddedData, data.length, paddedData.length, paddingByte);
		return paddedData;
	}

	private byte[] hashingPassword(String password, byte[] salt) throws Exception {
		String paddedPwd = paddingString(password, 128);

		byte[] pwdBytes = paddedPwd.getBytes();

		byte[] saltPwdBytes = new byte[pwdBytes.length + salt.length];

		System.arraycopy(pwdBytes, 0, saltPwdBytes, 0, pwdBytes.length);
		System.arraycopy(salt, 0, saltPwdBytes, pwdBytes.length, salt.length);

		byte[] hashPwd= hash_SHA256(saltPwdBytes);

		return hashPwd;
	}

	private byte[] longToBytes(long value) {
		ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
		buffer.putLong(value);
		return buffer.array();
	}

	private long bytesToLong(byte[] bytes) {
		long result = 0;
		for (int i = 0; i < bytes.length; i++) {
			result <<= 8;
			result |= (bytes[i] & 0xFF);
		}
		return result;
	}


	private byte[] getSalt(byte[] metadata) {
		byte[] salt = Arrays.copyOfRange(metadata, USER_LENGTH + PASS_LENGTH, HEADER_LENGTH);
		return salt;
	}


	private byte[] getESecretData(byte[] metadata) {
		byte[] encryptedSecretData = Arrays.copyOfRange(metadata, HEADER_LENGTH, METADATA_LENGTH);
		return encryptedSecretData;
	}

	private byte[] getHeader(byte[] metadata) {
		byte[] header = Arrays.copyOfRange(metadata, 0, HEADER_LENGTH);
		return header;
	}

	private byte[] getMetadata(String file_name) throws Exception{
		File dir = new File(file_name);
		File meta = new File(dir, "0");
		FileInputStream input = new FileInputStream(meta);
		byte[] metadata = input.readAllBytes();
		input.close();
		return metadata;
	}


	private byte[] getHashedPassword(byte[] metadata) {
		byte[] hashedPassword = Arrays.copyOfRange(metadata, USER_LENGTH, USER_LENGTH + PASS_LENGTH);
		return hashedPassword;

	}


	private boolean verifyPassword(byte[] metadata, String password) throws Exception {
		byte[] salt = getSalt(metadata);

		byte[] storedHashedPwd =  getHashedPassword(metadata);
		byte[] computedHashedPwd = hashingPassword(password, salt);

		return Arrays.equals(storedHashedPwd, computedHashedPwd);
	}

	private boolean verifyHMAC(byte[] metadata, String fileName) throws Exception {
		if (metadata.length != 1024) {
			throw new Exception();
		}

		byte[] data = getMetadata(fileName);
		byte[] hashPwd = getHashedPassword(data);

		byte [] metadataToCompare = Arrays.copyOfRange(data, 0, METADATA_LENGTH);
		byte [] storedHmac = Arrays.copyOfRange(data, METADATA_LENGTH, METADATA_LENGTH + HMAC_LENGTH);

		byte[] computedHmac = computeHMAC(hashPwd ,metadataToCompare);

		return Arrays.equals(storedHmac, computedHmac);
	}

	/**
	 * Steps to consider... <p>
	 *  - add padded username and password salt to header <p>
	 *  - add password hash and file length to secret data <p>
	 *  - AES encrypt padded secret data <p>
	 *  - add header and encrypted secret data to metadata <p>
	 *  - compute HMAC for integrity check of metadata <p>
	 *  - add metadata and HMAC to metadata file block <p>
	 */

	@Override
	public void create(String file_name, String user_name, String password) throws Exception {

		if (user_name.length() > USER_LENGTH || password.length() > PASS_LENGTH) {
			throw new IllegalArgumentException("user name and password are strings of at most 128 bytes.");
		}
		File dir = new File(file_name);
		dir.mkdirs();
		File meta = new File(dir, "0");
		meta.createNewFile();

		byte[] salt = secureRandomNumber(16);

		String paddedUser = paddingString(user_name, 128);

		byte[] hashedPwd = hashingPassword(password, salt);

		// Adding padded username and password salt to header
		byte[] header = new byte[paddedUser.length() + hashedPwd.length + salt.length];
		System.arraycopy(paddedUser.getBytes(), 0, header, 0, paddedUser.length());
		System.arraycopy(hashedPwd, 0, header, paddedUser.length(), hashedPwd.length);
		System.arraycopy(salt, 0, header, paddedUser.length() + hashedPwd.length, salt.length);

		byte[] fileLength = longToBytes(0);


		byte[] secretData = new byte[hashedPwd.length + fileLength.length];

		// Adding password hash and File length to secret data
		System.arraycopy(hashedPwd, 0, secretData, 0, hashedPwd.length);
		System.arraycopy(fileLength, 0, secretData, hashedPwd.length, fileLength.length);

		// Padding the secret data
		secretData = padWithPKCS7(secretData, 128);
		byte[] aesKey = generateKey(password, salt, KEY_LENGTH);
		byte[] encryptedSecretData = encryptAES_CTR(secretData, aesKey, salt);

		// Adding header and encrypted secret data to metadata
		byte[] metadata = new byte[header.length + encryptedSecretData.length];
		System.arraycopy(header, 0, metadata, 0, header.length);
		System.arraycopy(encryptedSecretData, 0, metadata, header.length, encryptedSecretData.length);

		// compute HMAC
		byte[] hmac = computeHMAC(hashedPwd, metadata);

		// add metadata and HMAC to metadata file block
		byte[] output = new byte[metadata.length + hmac.length];
		System.arraycopy(metadata, 0, output, 0, metadata.length);
		System.arraycopy(hmac, 0, output, metadata.length, hmac.length);

		output = padWithPKCS7(output, Config.BLOCK_SIZE);
		save_to_file(output, meta);
	}

	/**
	 * Steps to consider... <p>
	 *  - check if metadata file size is valid <p>
	 *  - get username from metadata <p>
	 */
	@Override
	public String findUser(String file_name) throws Exception {

		byte[] metadata = getMetadata(file_name);
		if(!verifyHMAC(metadata, file_name)) {
			throw new Exception("HMAC does not match");
		}

		byte[] paddedUsernameInBytes = Arrays.copyOfRange(metadata, 0, USER_LENGTH);
		String paddedUsername = new String(paddedUsernameInBytes);

		String username = paddedUsername.trim();

		return username;
	}

	/**
	 * Steps to consider...:<p>
	 *  - get password, salt then AES key <p>
	 *  - decrypt password hash out of encrypted secret data <p>
	 *  - check the equality of the two password hash values <p>
	 *  - decrypt file length out of encrypted secret data
	 */
	@Override
	public int length(String file_name, String password) throws Exception {
		byte[] metadata = getMetadata(file_name);

		if (!verifyPassword(metadata, password)) {
			throw new PasswordIncorrectException(); 
		}

		byte[] salt = getSalt(metadata);
		byte[] encryptedSecretData = getESecretData(metadata);
		byte[] aesKey = generateKey(password, salt, KEY_LENGTH);
		byte[] secretData = decryptAES_CTR(encryptedSecretData, aesKey, salt);

		long fileLength = bytesToLong(Arrays.copyOfRange(secretData, PASS_LENGTH, PASS_LENGTH + 8));
		int len = (int) fileLength;

		return len;
	}

	/**
	 * Steps to consider...:<p>
	 *  - verify password <p>
	 *  - check check if requested starting position and length are valid <p>
	 *  - decrypt content data of requested length
	 */
	@Override
	public byte[] read(String file_name, int starting_position, int len, String password) throws Exception {
		File root = new File(file_name);

		//verify password
		byte[] metadata = getMetadata(file_name);
		if (!verifyPassword(metadata, password)) {
			throw new PasswordIncorrectException(); 
		}

		int file_length = length(file_name, password);
		if (starting_position + len > file_length) {
			throw new Exception();
		}

		int start_block = starting_position / CONTENT_BLOCK_SIZE;

		int end_block = (starting_position + len) / CONTENT_BLOCK_SIZE;

		byte[] salt = getSalt(metadata);
		salt[0] += start_block;

		String toReturn = "";

		for (int i = start_block + 1; i <= end_block + 1; i++) {
			byte[] cipherTextWithPad= read_from_file(new File(root, Integer.toString(i)));
			byte[] cipherText = Arrays.copyOfRange(cipherTextWithPad, 0, CONTENT_BLOCK_SIZE) ;
			incrementCounter(salt);
			byte[] aesKey = generateKey(password, salt, KEY_LENGTH);
			byte[] plainText = decryptAES_CTR(cipherText, aesKey, salt);
			String temp = new String(plainText, "UTF-8");

			if (i == end_block + 1) {
				temp = temp.substring(0, starting_position + len - end_block * CONTENT_BLOCK_SIZE);
			}
			if (i == start_block + 1) {
				temp = temp.substring(starting_position - start_block * CONTENT_BLOCK_SIZE);
			}
			toReturn += temp;
		}

		return toReturn.getBytes();
	}


	//update meta data
	private void updateMetadata(int length, byte[] metadata, String file_name) throws Exception {
		byte[] fileLength = longToBytes(length);
		byte[] hashedPwd = getHashedPassword(metadata);
		byte[] secretData = new byte[hashedPwd.length + fileLength.length];
		byte[] salt = getSalt(metadata);

		System.arraycopy(hashedPwd, 0, secretData, 0, hashedPwd.length);
		System.arraycopy(fileLength, 0, secretData, hashedPwd.length, fileLength.length);

		// Padding the secret data
		secretData = padWithPKCS7(secretData, 128);
		byte[] aesKey = generateKey(password, salt, KEY_LENGTH);
		byte[] encryptedSecretData = encryptAES_CTR(secretData, aesKey, salt);
		byte[] header = getHeader(metadata);

		byte[] newMetadata = new byte[header.length + encryptedSecretData.length];

		System.arraycopy(header, 0, newMetadata, 0, header.length);
		System.arraycopy(encryptedSecretData, 0, newMetadata, header.length, encryptedSecretData.length);

		// compute HMAC
		byte[] hmac = computeHMAC(hashedPwd, newMetadata);

		// add metadata and HMAC to metadata file block
		byte[] output = new byte[newMetadata.length + hmac.length];
		System.arraycopy(newMetadata, 0, output, 0, newMetadata.length);
		System.arraycopy(hmac, 0, output, newMetadata.length, hmac.length);

		output = padWithPKCS7(output, Config.BLOCK_SIZE);

		File dir = new File(file_name);
		File metadataFile = new File(dir, "0");
		save_to_file(output, metadataFile);

	}


	/**
	 * Steps to consider...:<p>
	 *	- verify password <p>
	 *  - check check if requested starting position and length are valid <p>
	 *  - ### main procedure for update the encrypted content ### <p>
	 *  - compute new HMAC and update metadata
	 */
	@Override
	public void write(String file_name, int starting_position, byte[] content, String password) throws Exception {
		byte[] metadata = getMetadata(file_name);


		if (!verifyPassword(metadata, password)) {
			throw new PasswordIncorrectException();
		}

		String str_content = byteArray2String(content);
		File root = new File(file_name);
		int file_length = length(file_name, password);

		if (starting_position > file_length) {
			throw new Exception();
		}


		int len = str_content.length();
		int start_block = starting_position / CONTENT_BLOCK_SIZE;
		int end_block = (starting_position + len - 1) / CONTENT_BLOCK_SIZE;

		byte[] salt = getSalt(metadata);
		salt[0] += start_block;


		for (int i = start_block + 1; i <= end_block + 1; i++) {
			int sp = (i - 1) * CONTENT_BLOCK_SIZE - starting_position;
			int ep = (i) * CONTENT_BLOCK_SIZE - starting_position;
			String prefix = "";
			String postfix = "";

			incrementCounter(salt);

			byte[] aesKey = generateKey(password, salt, KEY_LENGTH);

			if (i == start_block + 1 && starting_position != start_block * CONTENT_BLOCK_SIZE) {
				byte[] cipherTextWithPad= read_from_file(new File(root, Integer.toString(i)));
				byte[] cipherText = Arrays.copyOfRange(cipherTextWithPad, 0, CONTENT_BLOCK_SIZE);
				byte[] plainText = decryptAES_CTR(cipherText, aesKey, salt);
				prefix = new String(plainText, "UTF-8");

				prefix = prefix.substring(0, starting_position - start_block * CONTENT_BLOCK_SIZE);
				sp = Math.max(sp, 0);
			}

			if (i == end_block + 1) {
				File end = new File(root, Integer.toString(i));
				if (end.exists()) {
					byte[] cipherTextWithPad= read_from_file(new File(root, Integer.toString(i)));
					byte[] cipherText = Arrays.copyOfRange(cipherTextWithPad, 0, CONTENT_BLOCK_SIZE);
					byte[] plainText = decryptAES_CTR(cipherText, aesKey, salt);
					postfix = new String(plainText, "UTF-8");

					if (postfix.length() > starting_position + len - end_block * CONTENT_BLOCK_SIZE) {
						postfix = postfix.substring(starting_position + len - end_block * CONTENT_BLOCK_SIZE);
					} else {
						postfix = "";
					}
				}
				ep = Math.min(ep, len);
			}

			
			String toWrite = prefix + str_content.substring(sp, ep) + postfix;
			byte[] toWriteInBytes = toWrite.getBytes();

			if(toWriteInBytes.length < CONTENT_BLOCK_SIZE){
				toWriteInBytes = padWithPKCS7(toWriteInBytes, CONTENT_BLOCK_SIZE);
			}


			byte[] cipherText = encryptAES_CTR(toWriteInBytes, aesKey, salt);

			byte[] hmac = computeHMAC(aesKey, cipherText);

			byte[] output = new byte[cipherText.length + hmac.length];

			System.arraycopy(cipherText, 0, output, 0, cipherText.length);
			System.arraycopy(hmac, 0, output, cipherText.length, hmac.length);


			output = padWithPKCS7(output, Config.BLOCK_SIZE);

			save_to_file(output, new File(root, Integer.toString(i)));
		}

		if (starting_position + len > length(file_name, password)){
			updateMetadata(starting_position + len, metadata, file_name);
		}
	}

	/**
	 * Steps to consider...:<p>
	 *  - verify password <p>
	 *  - check the equality of the computed and stored HMAC values for metadata and physical file blocks<p>
	 */
	@Override
	public boolean check_integrity(String file_name, String password) throws Exception {
		File dir = new File(file_name);
		byte[] metadata = getMetadata(file_name);
		if(!verifyPassword(metadata, password)) {
			throw new PasswordIncorrectException(); 
		}

		if(!verifyHMAC(metadata, file_name)) {
			throw new Exception("HMAC does not match");
		}

		int fileLength = length(file_name, password);
		int start_block = 1;
		int end_block = fileLength / CONTENT_BLOCK_SIZE;
		if (fileLength % CONTENT_BLOCK_SIZE != 0) {
			end_block += 1;
		}
		byte[] salt = getSalt(metadata);

		for (int i = start_block; i <= end_block; i++) {
			incrementCounter(salt);
			byte[] aesKey = generateKey(password, salt, KEY_LENGTH);
			File block = new File(dir, Integer.toString(i));

			byte[] data = read_from_file(block);

			byte[] contentToComputeHmac = Arrays.copyOfRange(data, 0, CONTENT_BLOCK_SIZE);
			byte[] storedHmac = Arrays.copyOfRange(data, CONTENT_BLOCK_SIZE, CONTENT_BLOCK_SIZE+ HMAC_LENGTH);
			byte[] computedHmac = computeHMAC(aesKey, contentToComputeHmac);
			
			if (!Arrays.equals(storedHmac, computedHmac)) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Steps to consider... <p>
	 *  - verify password <p>
	 *  - truncate the content after the specified length <p>
	 *  - re-pad, update metadata and HMAC <p>
	 */
	@Override
	public void cut(String file_name, int length, String password) throws Exception {
		byte[] metadata = getMetadata(file_name);

		if (!verifyPassword(metadata, password)) {
			throw new PasswordIncorrectException();

		}
		byte[] salt = getSalt(metadata);

		File root = new File(file_name);
		int fileLength = length(file_name, password);

		if (length > fileLength) {
			throw new Exception();
		}

		int end_block = (length) / CONTENT_BLOCK_SIZE;
		salt[0] += end_block+1;

		byte[] aesKey = generateKey(password, salt, KEY_LENGTH);
		byte[] cipherTextWithPad= read_from_file(new File(root, Integer.toString(end_block + 1)));
		byte[] cipherText = Arrays.copyOfRange(cipherTextWithPad, 0, CONTENT_BLOCK_SIZE);

		byte[] plainTextInBytes = decryptAES_CTR(cipherText, aesKey, salt);
		String plainText = new String(plainTextInBytes, "UTF-8");
		plainText = plainText.substring(0, length - end_block * CONTENT_BLOCK_SIZE);

		byte[] toWrite = plainText.getBytes();

		if(toWrite.length < CONTENT_BLOCK_SIZE){
			toWrite = padWithPKCS7(toWrite, CONTENT_BLOCK_SIZE);
		}


		byte[] encryptedSecretData = encryptAES_CTR(toWrite, aesKey, salt);
		byte[] hmac = computeHMAC(aesKey, encryptedSecretData);
		byte[] output= new byte[encryptedSecretData.length + hmac.length];

		System.arraycopy(encryptedSecretData, 0, output, 0, encryptedSecretData.length);
		System.arraycopy(hmac, 0, output, encryptedSecretData.length, hmac.length);

		output = padWithPKCS7(output, Config.BLOCK_SIZE);

		save_to_file(output, new File(root, Integer.toString(end_block+ 1)));


		int cur = end_block + 2;
		File file = new File(root, Integer.toString(cur));
		while (file.exists()) {
			file.delete();
			cur++;
		}

		//update meta data
		updateMetadata(length, metadata, file_name);
	}
}
