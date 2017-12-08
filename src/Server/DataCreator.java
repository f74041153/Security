package Server;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.text.SimpleDateFormat;
import java.util.Date;

import ezprivacy.secret.EnhancedProfileManager;
import ezprivacy.service.authsocket.EnhancedAuthSocketClient;
import ezprivacy.service.register.EnhancedProfileRegistrationClient;
import ezprivacy.toolkit.CipherUtil;

public class DataCreator {
	
	public static void main(String[] args)
	{
		EnhancedProfileManager profile;
		 try {
				profile = EnhancedProfileRegistrationClient.register();
				EnhancedAuthSocketClient client = new EnhancedAuthSocketClient(profile);
				client.connect("localhost", 81);
				client.doEnhancedKeyDistribution();
				System.out.println("[client] sk: " + client.getSessionKey());
				client.doRapidAuthentication();
				System.out.println("[client] auth: " + client.isAuthenticated());
				
				byte[] sk = client.getSessionKey().getKeyValue();
				byte[] k = CipherUtil.copy(sk, 0, CipherUtil.KEY_LENGTH);
				byte[] iv = CipherUtil.copy(sk, CipherUtil.KEY_LENGTH, CipherUtil.BLOCK_LENGTH);
				
				//String msg = "Data from App.";
				
				DataOutputStream out = new DataOutputStream(client.getOutputStream());
				while(true)
				{
					SimpleDateFormat sdFormat = new SimpleDateFormat("yyyy/MM/dd hh:mm:ss");
					Date date = new Date();
					String msg = sdFormat.format(date);
					byte[] encrypted_msg = CipherUtil.authEncrypt(k, iv, msg.getBytes());

					out.writeInt(encrypted_msg.length);
					out.write(encrypted_msg);
					out.flush();
					Thread.sleep(1000);
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
	}

}
