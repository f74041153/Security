package Server;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

import ezprivacy.protocol.IntegrityCheckException;
import ezprivacy.secret.EnhancedProfileManager;
import ezprivacy.service.authsocket.AuthSocketServer;
import ezprivacy.service.authsocket.EnhancedAuthSocketServerAcceptor;
import ezprivacy.service.register.EnhancedProfileRegistrationClient;
import ezprivacy.toolkit.CipherUtil;

public class MessageThread extends Thread{
	
	public static boolean family_flag=false;
	public static boolean local_flag=false;
	public static boolean emergency_flag=false;
	
	EnhancedProfileManager profile;
	EnhancedAuthSocketServerAcceptor serverAcceptor;
	AuthSocketServer clientSkt;
	String who;
	int port;
	
	public MessageThread(String who)
	{
		if(who.equals("family"))
		{
			this.who=who;
			port=6666;
		}else if(who.equals("local"))
		{
			this.who=who;
			port=6667;
		}
		else if(who.equals("emergency"))
		{
			this.who=who;
			port=6668;
		}
//		System.out.println(who);
		try {
			profile = EnhancedProfileRegistrationClient.register();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public void run()
	{
		serverAcceptor= new  EnhancedAuthSocketServerAcceptor(profile);
		try {
			serverAcceptor.bind(port);
			clientSkt= serverAcceptor.accept();
			clientSkt.waitUntilAuthenticated();
		} catch (Exception e) {
			e.printStackTrace();
		}
		System.out.println("連線成功");
		byte[] sk = clientSkt.getSessionKey().getKeyValue();
		byte[] k = CipherUtil.copy(sk, 0, CipherUtil.KEY_LENGTH);
		byte[] iv = CipherUtil.copy(sk, CipherUtil.KEY_LENGTH, CipherUtil.BLOCK_LENGTH);
		
		String rpns_msg = "hi, client.";
		PFC_CTR cipher_enc=new PFC_CTR(true,k);
		cipher_enc.setInitialVector(iv);
		cipher_enc.setStates(rpns_msg.getBytes());
		cipher_enc.execute();
		byte[] cipher_text=cipher_enc.getProcessedStates();
		System.out.println(new String(cipher_text));
		
		
		DataOutputStream out = new DataOutputStream(clientSkt.getOutputStream());
		try {
			while(true)
			{
				//check which thread
				if(who.equals("family"))
				{
					if(!access_family_flag(who))continue;
					else break;
				}
				else if(who.equals("local"))
				{
					if(!access_local_flag(who))continue;
				}else if(who.equals("emergency"))
				{
					if(!access_emergency_flag(who))continue;
				}
				
			}
			System.out.println("hi");
			out.writeInt(cipher_text.length);
			out.write(cipher_text);
			out.flush();
			Thread.sleep(1000);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			System.out.println("exception");
			e.printStackTrace();
		}
	}
	public synchronized static boolean access_family_flag(String id)
	{
		if(id.equals("Datafamily"))
		{
			family_flag=true;
			System.out.println(id);
		}
		else if(id.equals("family"))
		{
			if(!family_flag){
				return false;
			}
		}
		return true;
	}
	public synchronized static boolean access_local_flag(String id)
	{
		if(id.equals("Datalocal"))
		{
			local_flag=true;
		}
		else if(id.equals("local"))
		{
			if(!local_flag){
				return false;
			}			
		}
		return true;
	}
	public synchronized static boolean access_emergency_flag(String id)
	{
		if(id.equals("Dataemergency"))
		{
			emergency_flag=true;
		}
		else if(id.equals("emergency"))
		{
			if(!emergency_flag){
				return false;
			}			
		}
		return true;
	}
	
}
