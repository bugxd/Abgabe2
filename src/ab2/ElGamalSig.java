package ab2;

import java.math.BigInteger;

/**
 * Interface für die Verwendung des RSA-Kryptosystems.
 * 
 * @author Raphael Wigoutschnigg
 */
public interface ElGamalSig {
	/**
	 * Erzeugt eine geeignete Primzahl mit n-Bit Länge für das ElGamal-Kryptosystem
	 * 
	 * @param n
	 *            ... Länge der Primzahl
	 * @return Primzahl
	 */
	public BigInteger generatePrime(int n);

	/**
	 * Erzeugt mithilfe von p einen Geneator g
	 * 
	 * @param p
	 *            ... Modul des ElGamal-Verfahrens
	 * @return Generator
	 */
	public BigInteger generateGenerator(BigInteger p);

	/**
	 * Erzeugt den geheimen Schlüsselteil
	 * 
	 * @param p
	 *            ... Modul des ElGamal-Verfahrens
	 * @param g
	 *            ... Generator
	 * @return geheimer Schlüsselteil
	 */
	public BigInteger generatePrivatePart(BigInteger p);

	/**
	 * Erzeugt den öffentlichen Schlüsselteil
	 * 
	 * @param p
	 *            ... Modul des ElGamal-Verfahrens
	 * @param g
	 *            ... Generator
	 * @param d
	 *            ... Geheimer Schlüsselteil
	 * @return öffentlicher Schlüsselteil
	 */
	public BigInteger generatePublicPart(BigInteger p, BigInteger g, BigInteger d);

	/**
	 * Signiert eine Nachricht
	 * 
	 * @param message
	 *            ... zu verschlüsselnde Nachricht
	 * @param p
	 *            ... Modulus
	 * @param g
	 *            ... Generator
	 * @param d
	 *            ... geheimer Schlüsselteil
	 * @return
	 */
	public ElGamalSignature sign(byte[] message, BigInteger p, BigInteger g, BigInteger d);

	/**
	 * Verifiziert eine Nachricht
	 * 
	 * @param message
	 *            ... Signierte Nachricht
	 * @param sig
	 *            ... Signatur
	 * @param p
	 *            ... Modulus
	 * @param g
	 *            ... Generator
	 * @param e
	 *            ... öffentlicher Schlüsselteil
	 * @return true, wenn die Signatur zur Nachricht passt. Sonst false
	 */
	public boolean verify(byte[] message, ElGamalSignature sig, BigInteger p, BigInteger g, BigInteger e);

	/**
	 * Hilfsklasse zur Speicherung einer ElGamalSignatur
	 * 
	 * @author Raphael Wigoutschnigg
	 */
	public class ElGamalSignature {

		public ElGamalSignature()
		{
			
		}
		
		public ElGamalSignature(byte[] r, byte[] s) {
			super();
			this.r = r;
			this.s = s;
		}

		private byte[] r;
		private byte[] s;

		public byte[] getR() {
			return r;
		}

		public void setR(byte[] r) {
			this.r = r;
		}

		public byte[] getS() {
			return s;
		}

		public void setS(byte[] s) {
			this.s = s;
		}

	}
}
