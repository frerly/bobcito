/**
 * 
 */
package com.bobcito.xml.sign;

import java.io.ByteArrayInputStream;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import java.security.cert.CertificateEncodingException;
import javax.xml.bind.DatatypeConverter;

/**
 * 
 * Utilitarios para convertir 
 * @author frerly
 *
 */
public abstract class SignatureUtils {
	
	
	
	/**
	 * 
	 * */
	public static String privateKeyToString(PrivateKey privateKey)
			throws InvalidKeySpecException, NoSuchAlgorithmException {
		KeyFactory fact = KeyFactory.getInstance(privateKey.getAlgorithm());
		PKCS8EncodedKeySpec spec = fact.getKeySpec(privateKey, PKCS8EncodedKeySpec.class);
		byte[] packed = spec.getEncoded();
		String key64 = Base64.getEncoder().encodeToString(packed);

		Arrays.fill(packed, (byte) 0);
		return key64;
	}

	public static AlgorithmMethodType getAlgorithm(KeyStore keystore, String alias, char[] password)
			throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
		return AlgorithmMethodType.valueOf(keystore.getKey(alias, password).getAlgorithm().toString());

	}

	public static String privateKeyToString(KeyStore keystore, String alias, char[] password)
			throws InvalidKeySpecException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException {
		return privateKeyToString(getKey(keystore, alias, password));
	}

	public static PrivateKey stringToPrivateKey(String key64, AlgorithmMethodType algorithmMethodType)
			throws GeneralSecurityException {
		byte[] clear = Base64.getDecoder().decode(key64);
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(clear);
		KeyFactory fact = KeyFactory.getInstance(algorithmMethodType.name());
		PrivateKey priv = fact.generatePrivate(keySpec);
		Arrays.fill(clear, (byte) 0);
		return priv;
	}

	public static String x509CertificateToString(X509Certificate x509Certificate) throws CertificateEncodingException, CertificateEncodingException {
		String cert_begin = "-----BEGIN CERTIFICATE-----\n";
		String end_cert = "-----END CERTIFICATE-----";
		return cert_begin + DatatypeConverter.printBase64Binary(x509Certificate.getEncoded()) + end_cert;
	}

	public static String x509CertificateToString(KeyStore keystore, String alias, char[] password)
			throws CertificateEncodingException, KeyStoreException, java.security.cert.CertificateEncodingException {
		return x509CertificateToString(getCertKey(keystore, alias, password));
	}

	public static X509Certificate stringToX509Certificate(String stringx509Certificate)
			throws CertificateException, UnsupportedEncodingException {
		return (X509Certificate) CertificateFactory.getInstance("X.509")
				.generateCertificate(new ByteArrayInputStream(stringx509Certificate.getBytes("UTF-8")));
	}

	public static X509Certificate getCertKey(KeyStore keystore, String alias, char[] password)
			throws KeyStoreException {

		X509Certificate certificate = (X509Certificate) keystore.getCertificate(alias);
		return certificate;
	}

	public static PrivateKey getKey(KeyStore keystore, String alias, char[] password)
			throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
		return (PrivateKey) keystore.getKey(alias, password);
	}
}
