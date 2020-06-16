package com.adam.aslfms.service;

/**
 * This file is part of Simple Scrobbler.
 * <p/>
 * https://github.com/simple-last-fm-scrobbler/sls
 * <p/>
 * Copyright 2011 Simple Scrobbler Team
 * <p/>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p/>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p/>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import android.content.Context;
import android.os.Build;
import android.util.Log;

import com.adam.aslfms.util.AppSettings;
import com.adam.aslfms.util.AuthStatus;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;

import info.guardianproject.netcipher.NetCipher;

/**
 * Created by Debugs on 7/9/2016.
 *
 * @author Debugs
 * @since 1.5.0
 */

public class UserInfo extends NetRunnable {

    private static final String TAG = "UserInfo";

    protected AppSettings settings;
    Context mCtx;


    public UserInfo(NetApp napp, Context ctx, Networker net, AppSettings settings) {
        super(napp, ctx, net);
        this.settings = settings;
        this.mCtx = ctx;
    }

    public final void run() {
        NetApp netApp = getNetApp();
        String netAppName = netApp.getName();

        try {
            String response = getAllTimeScrobbles();

            JSONObject jObject = new JSONObject(response);
            if (jObject.has("payload")) {
                settings.setTotalScrobbles(getNetApp(), jObject.getJSONObject("payload").getString("count"));
                Log.i(TAG, "Get user info success: " + netAppName);
            } else if (jObject.has("user")) {
                settings.setTotalScrobbles(netApp, jObject.getJSONObject("user").getString("playcount"));
                Log.i(TAG, "Get user info success: " + netAppName);
            } else if (jObject.has("error")) {
                int code = jObject.getInt("error");
                if (code == 26 || code == 10) {
                    Log.e(TAG, "Get user info failed: client banned: " + netAppName);
                    settings.setSessionKey(netApp, "");
                    throw new AuthStatus.ClientBannedException("Now Playing failed because of client banned");
                } else if (code == 9) {
                    Log.i(TAG, "Get user info: bad auth: " + netAppName);
                    settings.setSessionKey(netApp, "");
                    throw new AuthStatus.BadSessionException("Now Playing failed because of badsession");
                } else {
                    Log.e(TAG, "Get user info fails: FAILED " + response + ": " + netAppName);
                    //settings.setSessionKey(netApp, "");
                    throw new AuthStatus.TemporaryFailureException("Now playing failed because of " + response);
                }

            } else {
                Log.d(TAG, "Failed to get user info.");
            }
        } catch (Exception e) {
            Log.e(TAG, "Get user info fail " + e);
            e.printStackTrace();
        }
    }

    private String getAllTimeScrobbles() throws IOException, NullPointerException {
        if (getNetApp() == NetApp.LISTENBRAINZ || getNetApp() == NetApp.LISTENBRAINZCUSTOM) {
            // TODO: Get total number of tracks in data base (make/wait for, pull request listenbrainz)
         /*   URL url;
            HttpsURLConnection conn = null;
            try {
                url = new URL(getNetApp().getWebserviceUrl(settings) + "user/" + settings.getUsername(getNetApp()) + "/listens");

                SSLContext sslContext = SSLContext.getInstance("TLS");
                sslContext.init(null, null, new java.security.SecureRandom());

                SSLSocketFactory customSockets = new MySecureSSLSocketFactory(sslContext.getSocketFactory(), new MyHandshakeCompletedListener());

                conn = NetCipher.getHttpsURLConnection(url);
                conn.setSSLSocketFactory(customSockets);

                /*String[] strArr = customSockets.getDefaultCipherSuites();
                for (String str : strArr) {
                    Log.e(TAG, str);
                }
                Log.e(TAG, strArr.length + " ..\n ..\n");
                Log.e(TAG, "HERE");
                strArr = customSockets.getSupportedCipherSuites();
                for (String str : strArr) {
                    Log.e(TAG, str);
                }

                // set Timeout and method
                // https://listenbrainz.readthedocs.io/en/latest/dev/api.html#webserver.views.api.DEFAULT_ITEMS_PER_GET
                conn.setReadTimeout(7000);
                conn.setConnectTimeout(7000);
                conn.setDoInput(true);
                conn.connect();

                int resCode = conn.getResponseCode();
                Log.d(TAG, "Response code: " + this.getNetApp().getName() + ": " + resCode);
                BufferedReader r;
                if (resCode == -1) {
                    return "";
                } else if (resCode == 200) {
                    r = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                } else {
                    r = new BufferedReader(new InputStreamReader(conn.getErrorStream()));
                }
                StringBuilder stringBuilder = new StringBuilder();
                String line;
                while ((line = r.readLine()) != null) {
                    stringBuilder.append(line);
                }
                String response = stringBuilder.toString();
                // Log.d(TAG, response);
                return response;
            } catch (Exception e) {
                Log.e(TAG, "Get user info fail " + e);
                e.printStackTrace();
            } finally {
                if (conn != null) {
                    conn.disconnect();
                }
            }*/
            return "{}";
        } else {
            URL url;
            HttpURLConnection insecConn = null;
            HttpsURLConnection conn = null;
            NetApp netApp = getNetApp();
            try {
                url = new URL(getNetApp().getWebserviceUrl(settings));

                Map<String, Object> params = new LinkedHashMap<>();
                params.put("method", "user.getInfo");
                params.put("user", settings.getUsername(getNetApp()));
                params.put("api_key", settings.rcnvK(settings.getAPIkey()));
                params.put("format", "json");

                StringBuilder postData = new StringBuilder();
                for (Map.Entry<String, Object> param : params.entrySet()) {
                    if (postData.length() != 0) postData.append('&');
                    postData.append(URLEncoder.encode(param.getKey(), "UTF-8"));
                    postData.append('=');
                    postData.append(URLEncoder.encode(String.valueOf(param.getValue()), "UTF-8"));
                }
                byte[] baseObj = postData.toString().getBytes("UTF-8");

                //Log.i(TAG, params.toString());

                int resCode = -1;
                // Create the SSL connection
                if (netApp == NetApp.LIBREFMCUSTOM && !settings.getSecureSocketLibreFm(netApp)) {
                    insecConn = (HttpsURLConnection) url.openConnection();

                    insecConn.setReadTimeout(10000);
                    insecConn.setConnectTimeout(10000);
                    insecConn.setRequestMethod("POST");
                    insecConn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
                    insecConn.setRequestProperty("Content-Length", String.valueOf(baseObj.length));
                    insecConn.setDoOutput(true);
                    insecConn.setDoInput(true);

                    DataOutputStream outStream = new DataOutputStream(insecConn.getOutputStream());
                    Log.d(TAG, baseObj.toString());
                    outStream.write(baseObj);
                    outStream.flush();
                    outStream.close();

                    insecConn.connect();
                    resCode = insecConn.getResponseCode();
                } else {
                    SSLContext sslContext = SSLContext.getInstance("TLS");
                    sslContext.init(null, null, new java.security.SecureRandom());

                    MySecureSSLSocketFactory customSockets = new MySecureSSLSocketFactory(sslContext.getSocketFactory(), new MyHandshakeCompletedListener());

                    conn = NetCipher.getHttpsURLConnection(url);
                    conn.setSSLSocketFactory(customSockets);

                    conn.setReadTimeout(10000);
                    conn.setConnectTimeout(10000);
                    conn.setRequestMethod("POST");
                    conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
                    conn.setRequestProperty("Content-Length", String.valueOf(baseObj.length));
                    conn.setDoOutput(true);
                    conn.setDoInput(true);

                    DataOutputStream outStream = new DataOutputStream(conn.getOutputStream());
                    Log.d(TAG, baseObj.toString());
                    outStream.write(baseObj);
                    outStream.flush();
                    outStream.close();

                    conn.connect();
                    resCode = conn.getResponseCode();
                }

                Log.d(TAG, "Response code: " + this.getNetApp().getName() + ": " + resCode);
                BufferedReader r;
                if (resCode == -1) {
                    return "{}";
                } else if (resCode == 200) {
                    r = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                } else {
                    r = new BufferedReader(new InputStreamReader(conn.getErrorStream()));
                }
                StringBuilder stringBuilder = new StringBuilder();
                String line;
                while ((line = r.readLine()) != null) {
                    stringBuilder.append(line).append('\n');
                }
                String response = stringBuilder.toString();
                Log.d(TAG, response);
                return response;
            } catch ( NoSuchAlgorithmException | KeyManagementException | IOException | NullPointerException e) {
                e.printStackTrace();
            } finally {
                if (conn != null) {
                    conn.disconnect();
                }
            }
        }
        return "{}";
    }
}

