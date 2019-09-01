import { Component, OnInit } from '@angular/core';
import { AuthService } from './auth/auth.service';

@Component({
  selector: 'app-callback',
  template: `
    <app-loading></app-loading>
  `
})
export class CallbackComponent implements OnInit {

  constructor(private auth: AuthService) { }
  /*
  Utilizaremos el componente de devolución de llamada para gestionar la redirección
  una vez que el usuario inicie sesión en nuestra aplicación. Es un componente muy simple.
  */
  ngOnInit() {
    /**
     *  El handleLoginCallback()método analizará el hash de autenticación,
     *  obtendrá la información de perfil del usuario,
     *  configurará su sesión y redireccionará a la ruta adecuada en la aplicación.
     */
    console.log('activando ');

    this.auth.handleLoginCallback();
  }

}
