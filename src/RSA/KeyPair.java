package RSA;

public class KeyPair {
	PublicKey publicKey;
	PrivateKey privateKey;

	public KeyPair(PublicKey publicKey, PrivateKey privateKey) {
		this.publicKey = publicKey;
		this.privateKey = privateKey;
	}

	public PublicKey getPublicKey() { return publicKey; }
	public PrivateKey getPrivateKey() { return privateKey; }
}