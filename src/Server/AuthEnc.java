package Server;


public abstract class AuthEnc extends EncMode
{
	public AuthEnc( boolean s, byte[] key ) {
		super(s,key);
	}
	
	public abstract void setInitialVector( byte[] init_vec );
	
	public abstract boolean check();
}

