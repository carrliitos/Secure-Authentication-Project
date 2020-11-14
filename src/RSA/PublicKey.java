package RSA;

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

public class PublicKey {
	BigInteger e;
	BigInteger n;

	public PublicKey(BigInteger e, BigInteger n) {
		this.e = e;
		this.n = n;
	}

	public PublicKey(String filepath) throws Exception {
		List<String> lines = Files.readAllLines(Paths.get(filepath), StandardCharsets.UTF_8);
		if(lines.size() != 2) {
			throw new Exception("There is a problem with the selected public key password file!");
		}else {
			BigInteger e = new BigInteger(lines.get(0), 16);
			BigInteger n = new BigInteger(lines.get(1), 16);
			this.e = e;
			this.n = n;
		}
	}

	public void saveToFile(String path) {
		BigInteger e = this.e;
		BigInteger n = this.n;
		try {
			PrintStream ps = new PrintStream(new File(path));
			ps.println(e.toString(16));
			ps.println(n.toString(16));
			ps.close();
		}catch(FileNotFoundException f) {
			System.out.println("FileNotFoundException: " + f.getMessage());
		}
	}

	public BigInteger getE() { return e; }
	public BigInteger getN() { return n; }
}