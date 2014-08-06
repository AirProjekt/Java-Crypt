package hr.foi.os.projekt;


import java.awt.EventQueue;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;

import java.awt.Font;
import javax.swing.JComboBox;
import javax.swing.LayoutStyle.ComponentPlacement;
import javax.swing.DefaultComboBoxModel;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.swing.UIManager;

public class MainFrame extends JFrame {

	/**
	 * 
	 */
	private static final long serialVersionUID = -3728095145072218725L;
	private JPanel contentPane;
	File file;

	/**
	 * Launch the application.
	 */
	
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					MainFrame frame = new MainFrame();
					frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the frame.
	 */
	public MainFrame() {
		setBackground(UIManager.getColor("activeCaption"));
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(100, 100, 519, 369);
		contentPane = new JPanel();
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		setContentPane(contentPane);
		
		JButton btnGenerirajKljueve = new JButton("Generiraj klju\u010Deve");
		btnGenerirajKljueve.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				//spremanje simetriènog kljuèa u datoteku tajni_kljuc.txt
				byte[] keyBytes = new byte[] {
				        'O','v','o','j','e','n','e','k','i','k','l','j','u','c','1','2'};
				 
				 try {
					FileWriter fileTajni = new FileWriter("tajni_kljuc.txt");
					String value = new String(keyBytes);
					fileTajni.write(value);
					fileTajni.close();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				//spremanje javnog kljuèa te privatnog kljuèa
				 try {
					KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
				    generator.initialize(1024);
				    KeyPair pair = generator.generateKeyPair();
				    Key pubKey = pair.getPublic();
				    Key privKey = pair.getPrivate();
				    byte[] pubKeyBytes = pubKey.getEncoded();
				    byte[] privKeyBytes = privKey.getEncoded();
				    FileOutputStream outPub = new FileOutputStream("javni_kljuc.txt");
				    outPub.write(pubKeyBytes);
				    outPub.close();
				    FileOutputStream outPriv = new FileOutputStream("privatni_kljuc.txt");
				    outPriv.write(privKeyBytes);
				    outPriv.close();
				    
				} catch (NoSuchAlgorithmException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		});
		
		JButton btnOdaberiDatoteku = new JButton("Odaberi datoteku");
		btnOdaberiDatoteku.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				JFileChooser fc = new JFileChooser();
			    // Show open dialog
			    fc.showOpenDialog(null);
			    file = fc.getSelectedFile();
			}
		});
		
		JLabel lblAlgoritam = new JLabel("Algoritam:");
		lblAlgoritam.setFont(new Font("Tahoma", Font.PLAIN, 15));
		
		final JComboBox<String> comboBox = new JComboBox<String>();
		comboBox.setFont(new Font("Tahoma", Font.PLAIN, 15));
		comboBox.setModel(new DefaultComboBoxModel<String>(new String[] {"Sinkroni", "Asinkroni"}));
		
		JButton btnEnkriptiraj = new JButton("Enkriptiraj");
		btnEnkriptiraj.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				int odabir = comboBox.getSelectedIndex();
				if (odabir == -1) {
					try {
						Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
						File fileKey = new File("tajni_kljuc.txt");
						byte[] input = new byte[(int) file.length()];
						byte[] keyBytes = new byte[(int) fileKey.length()];
						FileInputStream inKey = new FileInputStream(
								"tajni_kljuc.txt");
						FileInputStream in = new FileInputStream(file);
						in.read(input);
						inKey.read(keyBytes);
						in.close();
						inKey.close();
						SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
						Cipher cipher = Cipher.getInstance(
								"AES/ECB/PKCS7Padding", "BC");
						cipher.init(Cipher.ENCRYPT_MODE, key);
						byte[] cipherText = new byte[cipher
								.getOutputSize(input.length)];
						int ctLength = cipher.update(input, 0, input.length,
								cipherText, 0);
						ctLength += cipher.doFinal(cipherText, ctLength);
						FileOutputStream out = new FileOutputStream(file);
						out.write(cipherText);
						out.close();
					} catch (Exception e1) {
						JOptionPane.showMessageDialog(contentPane,
								"Niste odabrali niti jednu datoteku!");
						e1.printStackTrace();
					}
				}
				else{
					Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
					File filePublic = new File("javni_kljuc.txt");
					try {
						FileInputStream inPublic = new FileInputStream(filePublic);
						FileInputStream input = new FileInputStream(file);
						byte[] inputA = new byte[(int) file.length()];
					    byte[] publicKeyBytes = new byte[(int) filePublic.length()];
					    inPublic.read(publicKeyBytes);
					    inPublic.close();
					    input.read(inputA);
					    input.close();
					    Cipher cipher = Cipher.getInstance("RSA/None/PKCS1Padding", "BC");
					    KeyFactory keyFactory = KeyFactory.getInstance("RSA");

					    EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
					    PublicKey pubKey = keyFactory.generatePublic(publicKeySpec);
					    
					    cipher.init(Cipher.ENCRYPT_MODE, pubKey);
					    byte[] cipherText = cipher.doFinal(inputA);
					    FileOutputStream out = new FileOutputStream(file);
					    out.write(cipherText);
					    out.close();
					    
					} catch (Exception e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
					
				}
				
			}
		});
		
		JButton btnDekriptiraj = new JButton("Dekriptiraj");
		btnDekriptiraj.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				int odabir = comboBox.getSelectedIndex();
				Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
				if (odabir == -1) {
					File fileKey = new File("tajni_kljuc.txt");
					byte[] keyBytes = new byte[(int) fileKey.length()];
					FileInputStream inKey;
					FileInputStream in;
					FileOutputStream out;
					try {
						inKey = new FileInputStream("tajni_kljuc.txt");
						inKey.read(keyBytes);
						inKey.close();
						in = new FileInputStream(file);
						byte[] cipherText = new byte[(int) file.length()];
						in.read(cipherText);
						in.close();
						SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
						Cipher cipher = Cipher.getInstance(
								"AES/ECB/PKCS7Padding", "BC");
						cipher.init(Cipher.DECRYPT_MODE, key);
						byte[] plainText = new byte[cipher
								.getOutputSize((int) file.length())];
						int ptLength = cipher.update(cipherText, 0,
								(int) file.length(), plainText, 0);
						ptLength += cipher.doFinal(plainText, ptLength);
						out = new FileOutputStream(file);
						out.write(plainText);
						out.close();
					} catch (Exception e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
				else{
					File priv = new File("privatni_kljuc.txt");
					FileInputStream in;
					try {
						Cipher cipher = Cipher.getInstance("RSA/None/PKCS1Padding", "BC");
						in = new FileInputStream(priv);
						byte[] privateKeyBytes = new byte[(int) priv.length()];
						in.read(privateKeyBytes);
						in.close();
						
						KeyFactory keyFactory = KeyFactory.getInstance("RSA");
					    EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
					    PrivateKey privKey = keyFactory.generatePrivate(privateKeySpec);
					    FileInputStream input = new FileInputStream(file);
					    byte[] cipherText = new byte[(int) file.length()];
					    input.read(cipherText);
					    input.close();
					    cipher.init(Cipher.DECRYPT_MODE, privKey);
					    byte[] plainText = cipher.doFinal(cipherText);
					    FileOutputStream out = new FileOutputStream(file);
					    out.write(plainText);
					    out.close();
					    
					} catch (Exception e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					
				}
				
				
			}
		});
		
		JButton btnDigitalnoPotpii = new JButton("Digitalno potpi\u0161i");
		btnDigitalnoPotpii.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				try {
					File priv = new File("privatni_kljuc.txt");
					FileInputStream inPriv = new FileInputStream(priv);
					byte[] privateKeyBytes = new byte[(int) priv.length()];
					inPriv.read(privateKeyBytes);
					inPriv.close();
					
					KeyFactory keyFactory = KeyFactory.getInstance("RSA");
					EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
					PrivateKey privKey = keyFactory.generatePrivate(privateKeySpec);
					Signature signature = Signature.getInstance("SHA1withRSA");

				    signature.initSign(privKey);
				    FileInputStream in = new FileInputStream(file);
				    byte[] message = new byte[(int) file.length()];
				    in.read(message);
				    in.close();
				    signature.update(message);

				    byte[] sigBytes = signature.sign();
				    FileOutputStream out = new FileOutputStream("Potpisana poruka.txt");
				    out.write(sigBytes);
				    out.close();
				    JOptionPane.showMessageDialog(contentPane,
							"Datoteka je digitalno potpisana!");
				    
				} catch (Exception e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				
			}
		});
		
		JButton btnProvjeriDigitalnoPotpis = new JButton("Provjeri digitalni potpis");
		btnProvjeriDigitalnoPotpis.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				File filePublic = new File("javni_kljuc.txt");
				File fileSig = new File("Potpisana poruka.txt");
				try {
					FileInputStream inPublic = new FileInputStream(filePublic);
					byte[] publicKeyBytes = new byte[(int) filePublic.length()];
					inPublic.read(publicKeyBytes);
					inPublic.close();
					FileInputStream in = new FileInputStream(file);
					byte[] message = new byte[(int) file.length()];
					in.read(message);
					in.close();
					FileInputStream inSig = new FileInputStream(fileSig);
					byte[] sigBytes = new byte[(int) fileSig.length()];
					inSig.read(sigBytes);
					inSig.close();
					KeyFactory keyFactory = KeyFactory.getInstance("RSA");

				    EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
				    PublicKey pubKey = keyFactory.generatePublic(publicKeySpec);
				    Signature signature = Signature.getInstance("SHA1withRSA");
				    signature.initVerify(pubKey);
				    signature.update(message);
				    if(signature.verify(sigBytes)){
				    	JOptionPane.showMessageDialog(contentPane,
								"Digitalni potpis je uredan!");
				    }
				    else{
				    	JOptionPane.showMessageDialog(contentPane,
								"Digitalni potpis nije dobar!");
				    }
					
				} catch (Exception e1) {
					JOptionPane.showMessageDialog(contentPane,
							"Digitalni potpis nije dobar!");
					e1.printStackTrace();
				}
			}
		});
		GroupLayout gl_contentPane = new GroupLayout(contentPane);
		gl_contentPane.setHorizontalGroup(
			gl_contentPane.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_contentPane.createSequentialGroup()
					.addGroup(gl_contentPane.createParallelGroup(Alignment.LEADING)
						.addGroup(gl_contentPane.createSequentialGroup()
							.addGap(56)
							.addComponent(lblAlgoritam)
							.addPreferredGap(ComponentPlacement.RELATED)
							.addComponent(comboBox, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
							.addGap(46)
							.addGroup(gl_contentPane.createParallelGroup(Alignment.LEADING)
								.addGroup(gl_contentPane.createSequentialGroup()
									.addComponent(btnEnkriptiraj)
									.addGap(18)
									.addComponent(btnDekriptiraj))
								.addComponent(btnDigitalnoPotpii)
								.addComponent(btnProvjeriDigitalnoPotpis)))
						.addGroup(gl_contentPane.createSequentialGroup()
							.addGap(189)
							.addGroup(gl_contentPane.createParallelGroup(Alignment.TRAILING, false)
								.addComponent(btnOdaberiDatoteku, Alignment.LEADING, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
								.addComponent(btnGenerirajKljueve, Alignment.LEADING, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))))
					.addGap(56))
		);
		gl_contentPane.setVerticalGroup(
			gl_contentPane.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_contentPane.createSequentialGroup()
					.addGap(47)
					.addComponent(btnGenerirajKljueve, GroupLayout.PREFERRED_SIZE, 45, GroupLayout.PREFERRED_SIZE)
					.addGap(18)
					.addComponent(btnOdaberiDatoteku, GroupLayout.PREFERRED_SIZE, 45, GroupLayout.PREFERRED_SIZE)
					.addGap(42)
					.addGroup(gl_contentPane.createParallelGroup(Alignment.BASELINE)
						.addComponent(lblAlgoritam)
						.addComponent(btnEnkriptiraj)
						.addComponent(btnDekriptiraj)
						.addComponent(comboBox, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
					.addGap(20)
					.addComponent(btnDigitalnoPotpii)
					.addPreferredGap(ComponentPlacement.RELATED, 19, Short.MAX_VALUE)
					.addComponent(btnProvjeriDigitalnoPotpis)
					.addGap(13))
		);
		contentPane.setLayout(gl_contentPane);
	}
}
