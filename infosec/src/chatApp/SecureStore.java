package chatApp;

import java.security.KeyStore;
import java.security.KeyStoreSpi;
import java.security.Provider;

public class SecureStore extends KeyStore {

	protected SecureStore(KeyStoreSpi arg0, Provider arg1, String arg2) {
		super(arg0, arg1, arg2);
		// TODO Auto-generated constructor stub
	}

}
