//
//  HomeViewController.swift
//  Lovely-London-Example
//
//  Created by Kimi on 26/09/2019.
//  Copyright © 2019 Auth0. All rights reserved.
//

import UIKit
import Auth0
import Alamofire
import lovely_london


class HomeViewController: UIViewController {

    private var performFirstLogin = false
    
    @IBOutlet weak var activityIndicator: UIActivityIndicatorView!
    @IBOutlet weak var loginButton: UIButton!
    
    override func viewDidLoad() {
        super.viewDidLoad()
        activityIndicator.isHidden = true
        loginButton.isEnabled = false
    }

    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        if !performFirstLogin {
            performFirstLogin = false
            performLogin(self)
            return
        }
        loginButton.isEnabled = false
    }
    
    @IBAction func performLogin(_ sender: Any) {
        Auth0
            .webAuth()
            .scope("openid profile")
            .audience("https://coast-pilot-app.auth0.com/userinfo")
            .start { [weak self ] in
                guard let self = self else { return }
                switch $0 {
                case .failure(let error):
                    // Handle the error
                    print("Error: \(error)")
                    self.cancelLogin()
                case .success(let credentials):
                    // Do something with credentials e.g.: save them.
                    // Auth0 will automatically dismiss the login page
                    print("Credentials: \(credentials)")
                    self.loginWith(credentials: credentials)
                }
        }
    }
    
    private func logginIn() {
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            self.activityIndicator.isHidden = false
            self.activityIndicator.startAnimating()
            self.loginButton.isEnabled = false
        }
    }
    
    private func cancelLogin() {
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            self.activityIndicator.isHidden = true
            self.loginButton.isEnabled = true
        }
    }
    
    private func loginWith(credentials: Credentials) {
        logginIn()
        
        guard let idToken = credentials.idToken else {
            cancelLogin()
            return
        }
        
        Alamofire.request("https://coast-pilot-app.auth0.com/.well-known/openid-configuration").responseJSON { [weak self] response in
            print("Response JSON: \(response.value)")
            guard let self = self else { return }
            guard let json = response.value as? [String:Any] else {
                self.cancelLogin()
                return
            }
            guard let jwksURI = json["jwks_uri"] as? String,
                let issuer = json["issuer"] as? String else {
                self.cancelLogin()
                return
            }
        
            
            self.fetchJWKs(at: jwksURI) { keys in
                debugPrint("\(keys)")
                
                let verifier = IDTokenVerifier()
                    .require(claim: Claim.issuer(issuer))
                    .allowClockDifference(in: 5.0)
                
                for key in keys {
                    guard let n = key["n"] as? String,
                        let e = key["e"] as? String,
                        let kid = key["kid"] as? String,
                        let alg = key["alg"] as? String,
                        let signatureAlgorithm = SignatureAlgorithm.from(string: alg),
                        let secKey = self.secKeyFrom(mod: n, exp: e) else {
                            continue
                    }
                    
                    verifier
                    .require(claim: Claim.custom(claim: "kid", value: kid))
                    .set(signatureAlgorithm: signatureAlgorithm, and: secKey)
                    .verify(idToken: idToken,
                            onSuccess: { token in
                                debugPrint("\(token)")
                            },
                            onError: { error in
                                debugPrint("\(error)")
                            }
                    )
                }
            }
        }
    }
    
    private func fetchJWKs(at url: String, completion: @escaping (([[String:Any]])->Void)) {
        Alamofire.request(url).responseJSON { [weak self] response in
            print("Response JSON: \(response.value)")
            guard let self = self else { return }
            guard let json = response.value as? [String:Any] else {
                self.cancelLogin()
                return
            }
            guard let keys = json["keys"] as? [[String:Any]] else {
                self.cancelLogin()
                return
            }
            completion(keys)
        }
    }
    
    private func secKeyFrom(mod: String, exp: String) -> SecKey? {
        guard let modData = mod.data(using: .utf8),
            let expData = exp.data(using: .utf8) else {
                return nil
        }

        let data = Helper.generateRSAPublicKey(withModulus: modData, exponent: expData)
        
        if #available(iOS 10.0, iOSMac 10.0, OSX 10.0, watchOS 2.0, *) {
           let attrs: [CFString: Any] = [
               kSecAttrKeyType: kSecAttrKeyTypeRSA,
               kSecAttrKeyClass: kSecAttrKeyClassPublic
           ]
           
           var error: Unmanaged<CFError>?
           guard let key = SecKeyCreateWithData(data as CFData, attrs as CFDictionary, &error) else {
               return nil
           }
           return key
       }

        return nil
    }
}


