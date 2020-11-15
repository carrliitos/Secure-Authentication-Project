package MainView;

import RSA.*;
import java.awt.event.*;
import java.awt.*;
import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Random;
import javax.swing.*;

public class Main extends JFrame {
	public Main() {
		initComponents();
	}

	private void buttonProcessActionPerformed(ActionEvent e) {
		if(textField_a.getText().trim().equals("") || textField_b.getText().trim().equals("") || textField_p.getText().trim().equals("")) {
			JOptionPane.showMessageDialog(this, "Parameters a, b, p are required, please fill in completely", "prompt", JOptionPane.WARNING_MESSAGE);
		} else {
			BigInteger a = new BigInteger(textField_a.getText());
			BigInteger b = new BigInteger(textField_b.getText());
			BigInteger p = new BigInteger(textField_p.getText());
			BigInteger gx = new BigInteger(textField_gx.getText());
			BigInteger gy = new BigInteger(textField_gy.getText());
			try {
				keyPair = ECCryptoSystem.generateKeyPair(new EllipticCurve(a, b, p, new ECPoint(gx, gy)), new Random(System.currentTimeMillis()));
			} catch (Exception e1) {
				JOptionPane.showMessageDialog(this, e1.getMessage(), "prompt", JOptionPane.WARNING_MESSAGE);
				System.out.println("Exception: " + e1.getMessage());
			}
		}
	}

	private void comboBoxKindsActionPerformed(ActionEvent e) {
		int id = comboBoxKinds.getSelectedIndex();
		switch(id) {
			case 0 : 
				keyPair = null;
				setParametersTextField(null);
				break;
			case 1 :
				keyPair = null;
				setParametersTextField(NIST.P_192);
				break;
			case 2 :
				keyPair = null;
				setParametersTextField(NIST.P_256);
				break;
			case 3 :
				keyPair = null;
				setParametersTextField(NIST.P_384);
				break;
			case 4 :
				keyPair = null;
				setParametersTextField(NIST.P_521);
				break;
		}
	}
}