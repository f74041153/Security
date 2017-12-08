package Server;

import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import ezprivacy.toolkit.Converter;

/*usage:
 * use constructor to set switch:encryptor = true; decryptor = false
 * then setInitialVector and setStates(what you want to encrypt or decrypt)
 * use execute to start running
 * you can getProcessedStates to get the ciphertext||indicator
 * decryption vice versa
 * 
 * step-by-step:
 * 1.initialize this object
 * 2.get this object setInitialVector()
 * 3.get this object setStates()
 * 4.use execute() to start this cipher
 * 5.you can get result by using getProcessedStates() to get ciphertext or indicator
 */

public class PFC_CTR extends AuthEnc implements Runnable
{
	private byte[] initialVector;
	private byte[] tag;
	private byte[][] counters;
	private int blockSize;

	public PFC_CTR( boolean s, byte[] key ) {
		this(s, key, AES.BLOCK_LENGTH);
	}

	/**
	 * @param s The mode of encryption(true) or decryption(false)
	 * @param key The secret key that should be prepared previously
	 * @param block_size Define the block size of this encryptor in this PFC_CTR algorithm
	 * 
	 */
	public PFC_CTR( boolean s, byte[] key, int block_size ) {
		super(s, key);
		setBlockSize(block_size);
	}

	public void setBlockSize( int size ) {
		if ( size > AES.BLOCK_LENGTH )
			throw new IllegalArgumentException();
		else
			this.blockSize = size;
	}
	
	public int getBlockSize() {
		return this.blockSize;
	}

	public void setInitialVector( byte[] init_vec ) {
		if ( this.initialVector == null )
			this.initialVector = new byte [ AES.BLOCK_LENGTH ];
		if ( init_vec.length != AES.BLOCK_LENGTH )
			throw new IllegalArgumentException();
		System.arraycopy(init_vec, 0, this.initialVector, 0, init_vec.length);
	}

	/**
	 * @param states This can be plaintext during this object is set to be an encryptor, or it could be ciphertext during this is a decryptor.
	 */
	public void setStates( byte[] states ) {
		reset(getSwitch());
		if ( this.tag == null )
			this.tag = new byte [ this.blockSize ];
		if ( getSwitch() ) {
			this.states = split(states, this.blockSize);
		} else {
			byte[] states_ = new byte [ states.length-this.blockSize ];
			System.arraycopy(states, 0, states_, 0, states_.length);
			System.arraycopy(states, states.length-this.blockSize, this.tag, 0, this.blockSize);
			this.states = split(states_, this.blockSize);
		}
		this.processedStates = new byte [ this.states.length+1 ][ blockSize ];
		initLogger(this.states.length+1);

		if ( this.counters == null )
			this.counters = new byte [ this.states.length+1 ][ AES.BLOCK_LENGTH ];
		this.counters[0] = this.initialVector;
	}

	public byte[] getProcessedStates() {
		if ( getSwitch() )
			return concat(this.processedStates);
		else
			return concat(Arrays.copyOf(this.processedStates, this.processedStates.length-1));
	}

	public byte[] getIND() {
		return this.processedStates[this.processedStates.length-1];
	}
	
	public void execute() {
		startProcess();

		for ( int i=0; i<this.counters.length-1; i++ )
			this.counters[i+1] = nextCounter(i);

		if ( getSwitch() ) {
			ExecutorService pool = Executors.newFixedThreadPool(5);

			for ( int i=0; i<this.states.length+1; i++ )
				pool.execute(this);
			pool.shutdown();
			while ( !pool.isTerminated() ) {
			} // check and wait for all threads termination
		} else {
			for ( int i=0; i<this.states.length+1; i++ )
				run();
		}
		endProcess();
	}

	public void run() {
		int i = findNext();
		byte[] temp = new byte [ this.states[0].length ];

		startProcess(i);

		try {
			if ( getSwitch() ) {
				if ( i == 0 ) {
					System.arraycopy(AES.encrypt(this.counters[i], this.cipherKey), 0, temp, 0, temp.length);
					this.processedStates[i] = xor(this.states[i], temp);
				} else if ( i == this.states.length ) {
					System.arraycopy(AES.encrypt(xor(this.counters[i], this.states[i-1]), this.cipherKey), 0, temp, 0, temp.length);
					this.processedStates[i] = temp;
				} else {
					System.arraycopy(AES.encrypt(xor(this.counters[i], this.states[i-1]), this.cipherKey), 0, temp, 0, temp.length);
					this.processedStates[i] = xor(this.states[i], temp);
				}
			} else {
				if ( i == 0 ) {
					System.arraycopy(AES.encrypt(this.counters[i], this.cipherKey), 0, temp, 0, temp.length);
					this.processedStates[i] = xor(this.states[i], temp);
				} else if ( i == this.states.length ) {
					System.arraycopy(AES.encrypt(xor(this.counters[i], this.processedStates[i-1]), this.cipherKey), 0, temp, 0, temp.length);
					this.processedStates[i] = temp;
				} else {
					System.arraycopy(AES.encrypt(xor(this.counters[i], this.processedStates[i-1]), this.cipherKey), 0, temp, 0, temp.length);
					this.processedStates[i] = xor(this.states[i], temp);
				}
			}
		} catch ( Exception e ) {
			System.err.println("Exception happen during PFC_CTR.run().");
			e.printStackTrace();
		}
		endProcess(i);
	}

	public boolean check() {
		if ( getSwitch() ) {
			return false;
		} else {
			int l = this.processedStates.length - 1;
			return Arrays.equals(this.processedStates[l], this.tag);
		}
	}

	private byte[] nextCounter( int index ) {
		byte[] counter = new byte [ counters[index].length ];
		for ( int i=0; i<counter.length; i++ )
			counter[i] = (byte) (counters[index][i] + 1);
		return counter;
	}

	private byte[] xor( byte[] bytes1, byte[] bytes2 ) {
		byte[] retval = new byte [ bytes1.length ];
		byte[] temp = new byte [ bytes1.length ];
		System.arraycopy(bytes2, 0, temp, 0, bytes2.length);
		for ( int i=0; i<retval.length; i++ )
			retval[i] = (byte) (bytes1[i] ^ temp[i]);
		return retval;
	}
}
