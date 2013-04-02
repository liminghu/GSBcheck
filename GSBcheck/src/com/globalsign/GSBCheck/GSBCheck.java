package com.globalsign.GSBCheck;

import java.util.ArrayList;
import java.util.List;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;

import org.apache.log4j.Logger;
import org.postgresql.util.PSQLException;

import com.gsbcrawler.GSBCrawler;
import com.gsbanalyzer.GSBAnalyzer;
import com.gsbanalyzer.gsb.models.GSBInfectedUrl;

public class GSBCheck {

	private static Logger Log = Logger.getLogger(GSBCheck.class.getName());
    
		public static String getHttpResponseRabby(String location) {

		    String result = "";
		    URL url = null;
		    Log.debug("http:"+ "balance information");

		    try {
		        url = new URL(location);
		        Log.debug("http:"+"URL Link" + url);
		    } catch (MalformedURLException e) {
		        Log.error("http:"+ "URL Not found" + e.getMessage());
		    }

		    if (url != null) {
		        try {
		            BufferedReader in;
		            HttpURLConnection urlConn = (HttpURLConnection) url.openConnection();
		            urlConn.setConnectTimeout(1000);
		            while(true)
		            {
		                try 
		                    {
		                     in = new BufferedReader(new InputStreamReader(urlConn.getInputStream()));
		                    } 
		                catch (IOException e) 
		                    {
		                        break;
		                    }


		                String inputLine;

		                int lineCount = 0; // limit the lines for the example
		                while ((lineCount < 5) && ((inputLine = in.readLine()) != null)) 
		                    {
		                        lineCount++;

		                        result += inputLine;
		                    }

		                in.close();
		                urlConn.disconnect();
		                return result;
		           }
		        } catch (IOException e) {
		           Log.error("http:"+ "Retrive data" + e.getMessage());
		        }
		    } else {
		       Log.error("http:"+ "FAILED TO RETRIVE DATA" + " url NULL");
		    }
		    return result;
		}
	
	/*
	Using POST Method

	Client's request URL:

		https://sb-ssl.google.com/safebrowsing/api/lookup?client=firefox&apikey=12345&appver=1.5.2&pver=3.0

		Client's request Body:

		2
		http://www.google.com/
		http://ianfette.org/

		Server's response code:

		200

		Server's response body:

		ok
		malware

		In this example, the server responses with the state of the queried URLs one by one in the response body, 
		in the same order as in the request.
	 */
	public static void isMalicious() throws IOException
	{
		   //Safe Browsing Lookup API
		   //https://developers.google.com/safe-browsing/lookup_guide
		   String baseURL="https://sb-ssl.google.com/safebrowsing/api/lookup";
           //https://sb-ssl.google.com/safebrowsing/api/lookup?
		   //client=demo-app&apikey=12345&appver=1.5.2&pver=3.0&url=http%3A%2F%2Fianfette.org%2F
		   String arguments = "";
		   arguments +=URLEncoder.encode("client", "UTF-8") + "=" + URLEncoder.encode("myapp", "UTF-8") + "&";
		   
		   arguments +=URLEncoder.encode("apikey", "UTF-8") + "=" + URLEncoder.encode("ABQIAAAAJITJMgA23cKFczNFmGOKfhQVNDY5dS3MozaSszWw6_ovAoZkwQ", "UTF-8") 
				   + "&";
		   arguments +=URLEncoder.encode("appver", "UTF-8") + "=" + URLEncoder.encode("1.5.2", "UTF-8") + "&";
		   arguments +=URLEncoder.encode("pver", "UTF-8") + "=" + URLEncoder.encode("3.0", "UTF-8");

		   //String subjectURL = "";
		   //subjectURL +=URLEncoder.encode("url", "UTF-8") + "=" + URLEncoder.encode("http%3A%2F%2Fianfette.org%2F", "UTF-8");
		   // Construct the url object representing cgi script
		   URL url = new URL(baseURL + "?" + arguments); //+subjectURL

		   // Get a URLConnection object, to write to POST method
		   URLConnection connect = url.openConnection();

		   // Specify connection settings
		   connect.setDoInput(true);
		   connect.setDoOutput(true);

		   // Get an output stream for writing
		   OutputStream output = connect.getOutputStream();
		   PrintStream pout = new PrintStream (output);
		   pout.print("1");
		   //pout.println();
		   //pout.print("http://www.google.com");
		   pout.println();
		   pout.print("http://globalsign.com/");
		   
		   String result = "";
		   BufferedReader in = new BufferedReader(new InputStreamReader(connect.getInputStream()));
		   
		   String inputLine;

           int lineCount = 0; // limit the lines for the example
           while ((lineCount < 5) && ((inputLine = in.readLine()) != null)) 
               {
                   lineCount++;
                   result += inputLine;
               }

           in.close();
		   
           System.out.println(result);
           
		   pout.close();
	}
	
	public static void main(String[] args) throws PSQLException   {
		
		String DB_DRIVER = "org.postgresql.Driver";
		String DB_CONNECTION = "jdbc:postgresql://localhost/postgres"; 
		String DB_USER = "postgres";
		String DB_PASSWORD = "password";
		String SAFE_BROWSING = "http://safebrowsing.clients.google.com/safebrowsing";
		String GOOGLE_KEY = "ABQIAAAAJITJMgA23cKFczNFmGOKfhQVNDY5dS3MozaSszWw6_ovAoZkwQ";
		
		String output = null;
		String baseURL = "https://sb-ssl.google.com/safebrowsing/api/lookup?client=demo-app&apikey=ABQIAAAAJITJMgA23cKFczNFmGOKfhQVNDY5dS3MozaSszWw6_ovAoZkwQ&appver=1.5.2&pver=3.0&url=";
		String subjectURL = "http://ianfette.org/";
		output = getHttpResponseRabby(baseURL+subjectURL);
		
		//System.out.println(output);
		
		System.out.println("Google safe browsing query API result:");
		if(output.equals("malware") || output.equals("phishing") || output.equals("phishing,malware"))
		{
		  System.out.println(subjectURL+" is " + output+".");
		}
		else
		{
			  System.out.println(subjectURL+" is ok.");
		}
		
		String output2 = null;
		
		subjectURL = "http://globalsign.com/";
		output2 = getHttpResponseRabby(baseURL+subjectURL);
		
		//System.out.println(output2);
		
		
		if(output2.equals("malware") || output2.equals("phishing") || output2.equals("phishing,malware"))
		{
		  System.out.println(subjectURL+" is " + output2+".");
		}
		else
		{
		  System.out.println(subjectURL+" is ok.");
		}
		
		try {
			isMalicious();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		/*
		   0 to wait before next update
		   SELECT DISTINCT Hostkey, Count FROM "goog-malware-shavar_add_hosts" WHERE Hostkey = '292e6556'
           SELECT DISTINCT Hostkey, Count FROM "googpub-phish-shavar_add_hosts" WHERE Hostkey = '292e6556'
		 */
		
		System.out.println("Google safe browsing API local database result:");
		
		System.out.println("Updating the Google safe browsing API local database");
		GSBCrawler gsbCrawler = new GSBCrawler(GOOGLE_KEY, "", "", DB_CONNECTION, DB_USER, DB_PASSWORD);
		int timeToWait = gsbCrawler.updateDB();
		System.out.println(timeToWait+" seconds to wait before next update");
		   		                   
		List<String> domainsToCheck = new ArrayList<String>();
		System.out.println("checking domain name: ianfette.org");
		domainsToCheck.add("ianfette.org");
		//domainsToCheck.add("globalsign.com");
		//"YOUR_DB_PREFIX":""
		GSBAnalyzer gsbWrapper = new GSBAnalyzer(GOOGLE_KEY, SAFE_BROWSING,"", DB_CONNECTION, DB_USER, DB_PASSWORD);
		List<GSBInfectedUrl> gsbDirtyDomains=null;
		try {
			gsbDirtyDomains = gsbWrapper.analyzeWithGSB(domainsToCheck);
		} catch (PSQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println("Now output the result:");
		if(gsbDirtyDomains.size()>0)
			System.out.println("malware or phishing site.");
		
		for(GSBInfectedUrl gsbDirtyDomain : gsbDirtyDomains){
		       System.out.println(gsbDirtyDomain); 
		}
		
		domainsToCheck.clear();
		domainsToCheck.add("google.com");
		System.out.println("checking domain name: google.com");
		GSBAnalyzer gsbWrapper2 = new GSBAnalyzer(GOOGLE_KEY, SAFE_BROWSING,"", DB_CONNECTION, DB_USER, DB_PASSWORD);
		List<GSBInfectedUrl> gsbDirtyDomains2 = gsbWrapper2.analyzeWithGSB(domainsToCheck);
		System.out.println("Now output the result:");
		if(gsbDirtyDomains2.size()>0)
			System.out.println("malware or phishing site.");
		for(GSBInfectedUrl gsbDirtyDomain : gsbDirtyDomains2){
		       System.out.println(gsbDirtyDomain); 
		}
		
				
	}
}