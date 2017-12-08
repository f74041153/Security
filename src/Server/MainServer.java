package Server;

public class MainServer {

	public static void main(String[] args)
	{
		DataThread dt=new DataThread();	
		MessageThread family=new MessageThread("family");
		MessageThread local=new MessageThread("local");
		MessageThread emergency=new MessageThread("emergency");		
		
		dt.start();
		family.start();
		local.start();
		emergency.start();
	}
}
