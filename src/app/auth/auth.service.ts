import { Injectable } from '@angular/core';
import { Router } from '@angular/router';
import { environment } from './../../environments/environment';
import * as auth0 from 'auth0-js';
import * as firebase from 'firebase/app';
import { AngularFireAuth } from 'angularfire2/auth';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Subscription } from 'rxjs/Subscription';
import { Observable } from 'rxjs/Observable';
import { of } from 'rxjs/observable/of';
import { timer } from 'rxjs/observable/timer';
import { mergeMap } from 'rxjs/operators';
import Auth0Lock from 'auth0-lock';

@Injectable()
export class AuthService {
  // Create Auth0 web auth instance
  private _auth0 = new auth0.WebAuth({
    clientID: environment.auth.clientId,
    domain: environment.auth.clientDomain,
    responseType: 'token',
    redirectUri: environment.auth.redirect,
    audience: environment.auth.audience,
    scope: environment.auth.scope
  });
  accessToken: string;
  userProfile: any;
  // Track authentication status
  loggedIn: boolean;
  loading: boolean;
  // Track Firebase authentication status
  loggedInFirebase: boolean;
  // Subscribe to the Firebase token stream
  firebaseSub: Subscription;
  // Subscribe to Firebase renewal timer stream
  refreshFirebaseSub: Subscription;

  constructor(
    private router: Router,
    private afAuth: AngularFireAuth,
    private http: HttpClient
  ) {
    if (localStorage.getItem('authResult')) {
      console.log(JSON.parse(localStorage.getItem('authResult')));
      this.getUserInfo(JSON.parse(localStorage.getItem('authResult')));
    }
  }

  login(redirect?: string) {
    // Set redirect after login
    // - para redireccionar a la pagina que queriamos
    // ir antes de loguearnos
    const _redirect = redirect ? redirect : this.router.url;
    console.log('_redirect ', _redirect);
    localStorage.setItem('auth_redirect', _redirect);

    // Auth0 authorize request
    // tslint:disable-next-line:max-line-length

    /*authorize()método de Auth0 para ir
    a la página de inicio de sesión de Auth0*/
    this._auth0.authorize();
  }
  /*
  utilizan métodos Auth0 parseHash()y userInfo()para
  extraer resultados de autenticación y obtener el perfil del usuario respectivamente
  */
  handleLoginCallback() {
    console.log('activando ');
    this.loading = true;
    // When Auth0 hash parsed, get profile
    this._auth0.parseHash((err, authResult) => {
      console.log('authResult ', authResult); // resultado respecto a token de Auth0
      if (authResult && authResult.accessToken) {
        window.location.hash = '';
        // Store access token
        // this.accessToken = authResult.accessToken; // token de acceso
        localStorage.setItem('authResult', JSON.stringify(authResult));
        // Get user info: set up session, get Firebase token
        this.getUserInfo(authResult);
        // parseHash()y userInfo()para extraer resultados de autenticación y obtener el perfil del usuario
      } else if (err) {
        this.router.navigate(['/']);
        this.loading = false;
        console.error(`Error authenticating: ${err.error}`);
      }
    });
  }

  getUserInfo(authResult) {
    this.accessToken = authResult.accessToken;
    // Use access token to retrieve user's profile and set session
    // conseguir ek usuarios a partir del token generado
    this._auth0.client.userInfo(this.accessToken, (err, profile) => {
      if (profile) {
        console.log('getUserInfo: ', profile); // datos del usuario
        this._setSession(authResult, profile);
      } else if (err) {
        console.warn(`Error retrieving profile: ${err.error}`);
      }
    });
  }

  private _setSession(authResult, profile) {
    // Set tokens and expiration in localStorage
    const expiresAt = JSON.stringify((authResult.expiresIn * 1000) + Date.now()); // actualizando fecha de expiracion del token
    localStorage.setItem('expires_at', expiresAt);
    this.userProfile = profile;
    // Session set; set loggedIn and loading
    this.loggedIn = true; // confirmamos que esta logueado
    this.loading = false; // quitamos la pantalla de carga
    // Get Firebase token
    this._getFirebaseToken();
    // Redirect to desired route
    this.router.navigateByUrl(localStorage.getItem('auth_redirect'));
  }
  /*
   vamos a usar el token de acceso del resultado de autenticación
   para autorizar una solicitud HTTP a nuestra API para obtener un token de Firebase.
   Esto se hace con los métodos _getFirebaseToken()y _firebaseAuth():
  */
  private _getFirebaseToken() {
    // Prompt for login if no access token
    if (!this.accessToken) {
      this.login();
    }
    const getToken$ = () => {
      return this.http
        .get(`${environment.apiRoot}auth/firebase`, {
          headers: new HttpHeaders().set('Authorization', `Bearer ${this.accessToken}`)
        });
    };
    // nos subscribimos a una funcion getToken de firebase para obtner e token de firebase
    // desde la api en el servidor, claro enviamos en los headers el token de acceso de Auth0
    this.firebaseSub = getToken$().subscribe(
      res => this._firebaseAuth(res),
      err => console.error(`An error occurred fetching Firebase token: ${err.message}`)
    );
  }

  private _firebaseAuth(tokenObj) {
    console.log('tokenObj ', tokenObj); // token de firebase
    /**
     * autenticará con Firebase utilizando el signInWithCustomToken()método de Firebase .
     * Este método devuelve una promesa, y cuando se resuelva la promesa,
     * podemos decirle a nuestra aplicación que el inicio de sesión de Firebase fue exitoso
     */
    this.afAuth.auth.signInWithCustomToken(tokenObj.firebaseToken)
      .then(res => {

        this.loggedInFirebase = true;
        console.log('firebaseAuth res: ', res);
        // Schedule token renewal
        this.scheduleFirebaseRenewal();
        console.log('Successfully authenticated with Firebase!');
      })
      .catch(err => {
        const errorCode = err.code;
        const errorMessage = err.message;
        console.error(`${errorCode} Could not log into Firebase: ${errorMessage}`);
        this.loggedInFirebase = false;
      });
  }
// renovación automática de token de Firebase
  scheduleFirebaseRenewal() {
    // If user isn't authenticated, check for Firebase subscription
    // and unsubscribe, then return (don't schedule renewal)

    // Si el usuario no está autenticado, verifique la suscripción de Firebase
    // y darse de baja, luego regresar (no programar la renovación)
    console.log('this.firebaseSub ', this.firebaseSub);
    if (!this.loggedInFirebase) {
      if (this.firebaseSub) {
        this.firebaseSub.unsubscribe();
      }
      return;
    }
    // Unsubscribe from previous expiration observable
    this.unscheduleFirebaseRenewal();
    // Create and subscribe to expiration observable
    // Custom Firebase tokens minted by Firebase
    // expire after 3600 seconds (1 hour)
    const expiresAt = new Date().getTime() + (3600 * 1000);
    const expiresIn$ = of(expiresAt)
      .pipe(
        mergeMap(
          expires => {
            const now = Date.now();
            // Use timer to track delay until expiration
            // to run the refresh at the proper time
            return timer(Math.max(1, expires - now));
          }
        )
      );

    this.refreshFirebaseSub = expiresIn$
      .subscribe(
        () => {
          console.log('Firebase token expired; fetching a new one');
          this._getFirebaseToken(); // adquirimos nuevo token
        }
      );
  }

  unscheduleFirebaseRenewal() {
    console.log('this.refreshFirebaseSub ', this.refreshFirebaseSub);
    if (this.refreshFirebaseSub) {
      this.refreshFirebaseSub.unsubscribe();
    }
  }

  logout() {
    // Ensure all auth items removed
    localStorage.removeItem('expires_at');
    localStorage.removeItem('auth_redirect');
    localStorage.removeItem('authResult');
    this.accessToken = undefined;
    this.userProfile = undefined;
    this.loggedIn = false;
    // Sign out of Firebase
    this.loggedInFirebase = false;
    this.afAuth.auth.signOut();
    // Return to homepage
    this.router.navigate(['/']);
  }

  get tokenValid(): boolean {
    /**
     * El tokenValidmétodo de acceso comprueba si el token de acceso a Auth0 está vencido o no
     *  al comparar su caducidad con el datetime actual. Esto puede ser útil
     *  para determinar si el usuario necesita un nuevo token de acceso;
     *  no lo cubriremos en este tutorial, pero es posible que desee explorar
     * la renovación de la sesión de Auth0 por su cuenta.
     */

    // Check if current time is past access token's expiration
    const expiresAt = JSON.parse(localStorage.getItem('expires_at'));
    return Date.now() < expiresAt;
  }

}
