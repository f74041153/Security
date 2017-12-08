package Server;

import java.util.Arrays;


public abstract class EncMode
{
	private boolean switcher;  // encryptor = true; decryptor = false
	protected byte[] cipherKey = new byte [ AES.KEY_LENGTH ];
	protected byte[][] states;
	protected byte[][] processedStates;
	private int nextThread;
	
	//logger
	private boolean[] processed;
	private long[] jitter;
	private long latency;
	
	
	public EncMode( boolean s, byte[] key ) {
		reset(s);
		setKey(key);
	}
	
	
	protected void reset( boolean s ) {
		this.switcher = s;
		this.nextThread = 0;
	}
	
	public boolean getSwitch() {
		return this.switcher;
	}

	public void setKey( byte[] new_key ) {
		if ( new_key.length != AES.KEY_LENGTH )
			throw new IllegalArgumentException();
		System.arraycopy(new_key, 0, this.cipherKey, 0, new_key.length);
	}
	
	public void setStates( byte[] states ) {
		this.states = EncMode.split(states, AES.BLOCK_LENGTH);
		this.processedStates = new byte [ this.states.length ][ AES.BLOCK_LENGTH ];
		initLogger(this.states.length);
		this.nextThread = 0;
	}
	
	public byte[] getProcessedStates() {
		return EncMode.concat(this.processedStates);
	}
	
	protected void initLogger( int size ) {
		this.processed = new boolean [ size ];
		Arrays.fill(this.processed, false);
		this.jitter = new long [ size ];
		Arrays.fill(this.jitter, 0);
		this.latency = 0;
	}
	

	//logger
	protected void startProcess() {
		this.latency = -System.nanoTime();
	}
	
	protected void endProcess() {
		this.latency += System.nanoTime();
	}
	
	protected void startProcess( int index ) {
		this.jitter[index] = -System.nanoTime();
	}
	
	protected void endProcess( int index ) {
		this.jitter[index] += System.nanoTime();
		this.processed[index] = true;
	}
	
	
	public long[] getJitter() {
		return this.jitter;
	}
	
	public long getLatency() {
		return this.latency;
	}
	
	public boolean isProcessed( int i ) {
		return this.processed[i];
	}
	
	public boolean isProcessed() {
		boolean i = this.processed[0];
		for( boolean k : this.processed ) i &= k;
		return i;
	}
	
	public static byte[][] split( byte[] msg, int length ) {
		byte[][] states = new byte[ (msg.length-1)/length+1 ][ length ];
		for ( int i=0; i<states.length; i++ )
			states[i] = Arrays.copyOfRange(msg, i*length, (i+1)*length);
		return states;
	}
	
	public static byte[] concat( byte[][] states ) {
		int width = states[0].length;
		byte[] temp = new byte [ states.length*width ];
		for ( int i=0; i<states.length; i++ )
			System.arraycopy( states[i], 0, temp, i*width, width);
		
		int padding = 0;  // depadding
		for ( int i=temp.length-1; temp[i]==0; i-- )
				padding++;
		byte[] msg = new byte [ temp.length-padding ];
		System.arraycopy(temp, 0, msg, 0, msg.length);
		return msg;
	}
	
	
	//core
	public abstract void execute();
	
	public abstract void run();
	
	protected synchronized int findNext() {
		return this.nextThread++;
	}
}

