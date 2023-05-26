package uk.ac.ncl.cascade.zkpgs.message;

import org.junit.Assert;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.ac.ncl.cascade.zkpgs.store.URN;
import java.io.IOException;
import java.util.HashMap;

class GSServerAsyncTest {
	private HashMap<URN, Object> messageElements;
	private GSMessage message;
	private GSServerAsync serverAsync;

	@BeforeEach
	void setUp() {
		serverAsync = new GSServerAsync(1233);
	}

	@AfterEach
	void tearDown() {
	}

	@Test
	void init() throws IOException {
		serverAsync.init();
	}
}