package Server;

import java.io.DataInputStream;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.StringTokenizer;

import com.mysql.jdbc.PreparedStatement;

import ezprivacy.secret.EnhancedProfileManager;
import ezprivacy.service.authsocket.AuthSocketServer;
import ezprivacy.service.authsocket.EnhancedAuthSocketServerAcceptor;
import ezprivacy.service.register.EnhancedProfileRegistrationClient;
import ezprivacy.toolkit.CipherUtil;

public class DataThread extends Thread{

	EnhancedProfileManager profile;
	EnhancedAuthSocketServerAcceptor serverAcceptor;
	AuthSocketServer clientSkt;
	int port=81;
	
	private static Connection con=null;
	String url="jdbc:mysql://localhost/healthcaredata?useUnicode=true&characterEncoding=Big5";
	String user="notroot";
	String password="dbforsensor";
	
	public DataThread()
	{
		 try {
			profile = EnhancedProfileRegistrationClient.register();
		} catch (Exception e) {
			e.printStackTrace();
		}
		 try{
			Class.forName("com.mysql.jdbc.Driver");// 載入 JDBC 的驅動程式
			System.out.println("載入驅動程式成功");
			con=DriverManager.getConnection(url,user,password);//Java 程式和資料庫之間的連線
			System.out.println("database連線成功");
		}catch(ClassNotFoundException e){
			System.out.println("DriverClassNotFound:"+e.toString());//找不到驅動程式
		}catch(SQLException x){
			System.out.println("Exception:"+x.toString());
		}
	}
	public void run()
	{
		serverAcceptor= new  EnhancedAuthSocketServerAcceptor(profile);
		try {
			serverAcceptor.bind(port);
			clientSkt= serverAcceptor.accept();
			clientSkt.waitUntilAuthenticated();
			DataInputStream in = new DataInputStream(clientSkt.getInputStream());
			while(true)
			{
				int msg_length = in.readInt();
				byte[] encrypted_msg = new byte [ msg_length ];
				in.readFully(encrypted_msg);
	
				byte[] sk = clientSkt.getSessionKey().getKeyValue();
				byte[] k = CipherUtil.copy(sk, 0, CipherUtil.KEY_LENGTH);
				byte[] iv = CipherUtil.copy(sk, CipherUtil.KEY_LENGTH, CipherUtil.BLOCK_LENGTH);
	
				String msg = new String(CipherUtil.authDecrypt(k, iv, encrypted_msg));
				StringTokenizer st = new StringTokenizer(msg," ");
				String date = null,time = null;
				if(st.hasMoreTokens())date=st.nextToken();
				if(st.hasMoreTokens())time=st.nextToken();
				if(time.equals("07:48:00"))MessageThread.access_family_flag("Datafamily");
				else if(time.equals("03:41:30"))MessageThread.access_local_flag("Datalocal");
				else if(time.equals("03:42:30"))MessageThread.access_emergency_flag("Dataemergency");
				//System.out.println("client say:date="+date+" time="+time);
			//	insertTable(date,time);
			}

		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	/*sql*/
	private PreparedStatement pst=null;
	private String insertdbSQL = "insert into user(date,time)VALUES (?, ?) ";	
	public void insertTable(String date,String time)
	{
		try{
			pst=(PreparedStatement) con.prepareStatement(insertdbSQL);
			
			pst.setString(1, date);
			pst.setString(2, time);
			pst.executeUpdate();
			//System.out.println("insert");
		}catch(Exception e){
			System.out.println("InsertDB Exception :" + e.toString()); 
		}finally{
			Close();
		}
	}
	private void Close()//資源釋放
	{
		try{
			 if(pst!=null) 
		      { 
		        pst.close(); 
		        pst = null; 
		      } 
		}catch(Exception e){
			System.out.println("Close Exception :" + e.toString()); 
		}
	}
}
