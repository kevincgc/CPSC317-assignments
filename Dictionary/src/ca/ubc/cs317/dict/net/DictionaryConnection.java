package ca.ubc.cs317.dict.net;

import ca.ubc.cs317.dict.model.Database;
import ca.ubc.cs317.dict.model.Definition;
import ca.ubc.cs317.dict.model.MatchingStrategy;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.*;

/**
 * Created by Jonatan on 2017-09-09.
 */
public class DictionaryConnection {

	private static final int DEFAULT_PORT = 2628;
	private Socket socket;
	BufferedReader input;
	PrintWriter output;
	Status stat;

	/**
	 * Establishes a new connection with a DICT server using an explicit host and
	 * port number, and handles initial welcome messages.
	 *
	 * @param host Name of the host where the DICT server is running
	 * @param port Port number used by the DICT server
	 * @throws DictConnectionException If the host does not exist, the connection
	 *                                 can't be established, or the messages don't
	 *                                 match their expected value.
	 */
	public DictionaryConnection(String host, int port) throws DictConnectionException {
		try {
			socket = new Socket(host, port);
			input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			output = new PrintWriter(socket.getOutputStream());
			stat = Status.readStatus(input);

			if (stat.getStatusCode() == 220) {
				System.out.println("Connected! Welcome message: " + stat.getDetails());
			} else {
				throw new DictConnectionException("Expected code 220 but received " + stat.getStatusCode());
			}
		} catch (IOException e) {
			throw new DictConnectionException("Connection to " + host + " has failed", e);
		} catch (NoSuchElementException e) {
			throw new DictConnectionException("Expected welcome message but none received", e);
		}
	}

	/**
	 * Establishes a new connection with a DICT server using an explicit host, with
	 * the default DICT port number, and handles initial welcome messages.
	 *
	 * @param host Name of the host where the DICT server is running
	 * @throws DictConnectionException If the host does not exist, the connection
	 *                                 can't be established, or the messages don't
	 *                                 match their expected value.
	 */
	public DictionaryConnection(String host) throws DictConnectionException {
		this(host, DEFAULT_PORT);
	}

	/**
	 * Sends the final QUIT message and closes the connection with the server. This
	 * function ignores any exception that may happen while sending the message,
	 * receiving its reply, or closing the connection.
	 *
	 */
	public synchronized void close() {
		try {
			output.println("QUIT");
			output.flush();
			stat = Status.readStatus(input); // Expects code 221
			System.out.println("Sent QUIT. Response: " + stat.getStatusCode());

			socket.close();
			System.out.println("Connection has been closed!");
		} catch (IOException | DictConnectionException e) {
			// Error is ignored
		}
	}

	/**
	 * Requests and retrieves all definitions for a specific word.
	 *
	 * @param word     The word whose definition is to be retrieved.
	 * @param database The database to be used to retrieve the definition. A special
	 *                 database may be specified, indicating either that all regular
	 *                 databases should be used (database name '*'), or that only
	 *                 definitions in the first database that has a definition for
	 *                 the word should be used (database '!').
	 * @return A collection of Definition objects containing all definitions
	 *         returned by the server.
	 * @throws DictConnectionException If the connection was interrupted or the
	 *                                 messages don't match their expected value.
	 */
	public synchronized Collection<Definition> getDefinitions(String word, Database database)
			throws DictConnectionException {
		Collection<Definition> set = new ArrayList<>();
		output.println("DEFINE " + database.getName() + " " + word);
		output.flush();
		stat = Status.readStatus(input);

		if (stat.getStatusCode() == 150) {
			int definitionCount = Integer.parseInt(DictStringParser.splitAtoms(stat.getDetails())[0]);
			try {
				for (int i = 0; i < definitionCount; i++) {
					stat = Status.readStatus(input);
					Definition definition = new Definition(word, DictStringParser.splitAtoms(stat.getDetails())[1]);
					String str = input.readLine();
					while (!(str.contains(".") && str.length() < 2)) {
						definition.appendDefinition(str);
						str = input.readLine();
					}
					set.add(definition);
				}
				stat = Status.readStatus(input);
				
				if (stat.getStatusCode() != 250) {
					throw new DictConnectionException("Expected code 250 but received " + stat.getStatusCode());
				}
			} catch (IOException e) {
				throw new DictConnectionException("Connection issue in getDefinitions: ", e);
			}
			System.out.println("Finished adding " + set.size() + " definitions!");
		} else if (stat.getStatusCode() == 550) {
			System.out.println("Code 550 Invalid DB in getDefinitions");
		} else if (stat.getStatusCode() == 552) {
			System.out.println("Code 552 No Definitions in getDefinitions");
		} else {
			throw new DictConnectionException("Unexpected code " + stat.getStatusCode() + " in getDefinitions");
		}

		return set;
	}

	/**
	 * Requests and retrieves a list of matches for a specific word pattern.
	 *
	 * @param word     The word whose definition is to be retrieved.
	 * @param strategy The strategy to be used to retrieve the list of matches
	 *                 (e.g., prefix, exact).
	 * @param database The database to be used to retrieve the definition. A special
	 *                 database may be specified, indicating either that all regular
	 *                 databases should be used (database name '*'), or that only
	 *                 matches in the first database that has a match for the word
	 *                 should be used (database '!').
	 * @return A set of word matches returned by the server.
	 * @throws DictConnectionException If the connection was interrupted or the
	 *                                 messages don't match their expected value.
	 */
	public synchronized Set<String> getMatchList(String word, MatchingStrategy strategy, Database database)
			throws DictConnectionException {
		Set<String> set = new LinkedHashSet<>();
		output.println("MATCH " + database.getName() + " " + strategy.getName() + " " + word);
		output.flush();
		stat = Status.readStatus(input);

		if (stat.getStatusCode() == 152) {
			int matchCount = Integer.parseInt(DictStringParser.splitAtoms(stat.getDetails())[0]);
			try {
				for (int i = 0; i < matchCount; i++) {
					String match = input.readLine();
					set.add(DictStringParser.splitAtoms(match)[1]);
				}
				input.readLine();
				stat = Status.readStatus(input);
				
				if (stat.getStatusCode() != 250) {
					throw new DictConnectionException(
							"Expected code 250 in getMatchList but received " + stat.getStatusCode());
				}
			} catch (IOException e) {
				throw new DictConnectionException("Connection issue in getMatchList: ", e);
			}
		} else if (stat.getStatusCode() == 550) {
			System.out.println("Code 550 Invalid DB in getMatchList");
		} else if (stat.getStatusCode() == 551) {
			System.out.println("Code 551 Invalid Strategy in getMatchList");
		} else if (stat.getStatusCode() == 552) {
			System.out.println("Code 552 No Matches in getMatchList");
		} else {
			throw new DictConnectionException("Unexpected code " + stat.getStatusCode() + " in getMatchList");
		}

		return set;
	}

	/**
	 * Requests and retrieves a map of database name to an equivalent database
	 * object for all valid databases used in the server.
	 *
	 * @return A map of Database objects supported by the server.
	 * @throws DictConnectionException If the connection was interrupted or the
	 *                                 messages don't match their expected value.
	 */
	public synchronized Map<String, Database> getDatabaseList() throws DictConnectionException {
		Map<String, Database> databaseMap = new HashMap<>();
		output.println("SHOW DB");
		output.flush();
		stat = Status.readStatus(input);
		
		if (stat.getStatusCode() == 110) {
			int dbCount = Integer.parseInt(DictStringParser.splitAtoms(stat.getDetails())[0]);
			try {
				for (int i = 0; i < dbCount; i++) {
					String db = input.readLine();
					databaseMap.put(DictStringParser.splitAtoms(db)[0],
							new Database(DictStringParser.splitAtoms(db)[0], DictStringParser.splitAtoms(db)[1]));
				}
				input.readLine();
				stat = Status.readStatus(input);
				
				if (stat.getStatusCode() != 250) {
					throw new DictConnectionException(
							"Expected code 250 in getDatabaseList but received " + stat.getStatusCode());
				}
			} catch (IOException e) {
				throw new DictConnectionException("Connection issue in getDatabaseList: ", e);
			}
			System.out.println("Finished adding " + databaseMap.size() + " databases!");
		} else if (stat.getStatusCode() == 554) {
			System.out.println("Code 554 No databases present in getDatabaseList");
		} else {
			throw new DictConnectionException("Unexpected code " + stat.getStatusCode() + " in getDatabaseList");
		}
		
		return databaseMap;
	}

	/**
	 * Requests and retrieves a list of all valid matching strategies supported by
	 * the server.
	 *
	 * @return A set of MatchingStrategy objects supported by the server.
	 * @throws DictConnectionException If the connection was interrupted or the
	 *                                 messages don't match their expected value.
	 */
	public synchronized Set<MatchingStrategy> getStrategyList() throws DictConnectionException {
		Set<MatchingStrategy> set = new LinkedHashSet<>();
		output.println("SHOW STRAT");
		output.flush();
		stat = Status.readStatus(input);
		
		if (stat.getStatusCode() == 111) {
			int stratCount = Integer.parseInt(DictStringParser.splitAtoms(stat.getDetails())[0]);
			try {
				for (int i = 0; i < stratCount; i++) {
					String strat = input.readLine();
					set.add(new MatchingStrategy(DictStringParser.splitAtoms(strat)[0],
							DictStringParser.splitAtoms(strat)[1]));
				}
				input.readLine();
				stat = Status.readStatus(input);
				
				if (stat.getStatusCode() != 250) {
					throw new DictConnectionException(
							"Expected code 250 in getStrategyList but received " + stat.getStatusCode());
				}
			} catch (IOException e) {
				throw new DictConnectionException("Connection issue in getStrategyList: ", e);
			}
			System.out.println("Finished adding " + set.size() + " strategies!");
		} else if (stat.getStatusCode() == 555) {
			System.out.println("Code 555 No strategies present in getStrategyList");
		} else {
			throw new DictConnectionException("Unexpected code " + stat.getStatusCode() + " in getStrategyList");
		}

		return set;
	}
}
