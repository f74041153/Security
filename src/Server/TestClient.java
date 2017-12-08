package Server;

import java.io.DataInputStream;
import java.io.DataOutputStream;

import ezprivacy.secret.EnhancedProfileManager;
import ezprivacy.service.authsocket.EnhancedAuthSocketClient;
import ezprivacy.service.register.EnhancedProfileRegistrationClient;
import ezprivacy.toolkit.CipherUtil;

public class TestClient {
	
	public static void main(String[] args)
	{
		EnhancedProfileManager profile;
		 try {
				profile = EnhancedProfileRegistrationClient.register();
				EnhancedAuthSocketClient client = new EnhancedAuthSocketClient(profile);
				client.connect("localhost", 6666);
				client.doEnhancedKeyDistribution();
				System.out.println("[client] sk: " + client.getSessionKey());
				client.doRapidAuthentication();
				System.out.println("[client] auth: " + client.isAuthenticated());
				
				byte[] sk = client.getSessionKey().getKeyValue();
				byte[] k = CipherUtil.copy(sk, 0, CipherUtil.KEY_LENGTH);
				byte[] iv = CipherUtil.copy(sk, CipherUtil.KEY_LENGTH, CipherUtil.BLOCK_LENGTH);
				
				
				DataInputStream in = new DataInputStream(client.getInputStream());
				while(true)
				{
					int msg_length = in.readInt();
					byte[] encrypted_rcvd_msg = new byte [ msg_length ];
					in.readFully(encrypted_rcvd_msg);
	
					String rcvd_msg = new String(CipherUtil.authDecrypt(k, iv, encrypted_rcvd_msg));
					System.out.println("server say: " + rcvd_msg);
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
		
	}
	
	
	

}
