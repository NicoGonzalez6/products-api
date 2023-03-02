import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { CognitoIdentityServiceProvider } from 'aws-sdk';
import CognitoExpress from 'cognito-express';
import { IncomingHttpHeaders } from 'http';

@Injectable()
export class CognitoServices {
  constructor(private configService: ConfigService) {}

  cognito = {
    AWS_REGION: this.configService.get('AWS_REGION'),
    COGNITO_USER_POOL_ID: this.configService.get('COGNITO_USER_POOL_ID'),
    COGNITO_CLIENT_ID: this.configService.get('COGNITO_CLIENT_ID'),
  };

  cognitoIdentityServiceProvider = new CognitoIdentityServiceProvider({
    region: this.cognito.AWS_REGION,
  });

  cognitoExpress = new CognitoExpress({
    region: this.cognito.AWS_REGION,
    cognitoUserPoolId: this.cognito.COGNITO_USER_POOL_ID,
    tokenUse: 'access',
    tokenExpiration: 3600,
  });

  getUserRole(cognitoGroups: string[]) {
    return cognitoGroups?.[0];
  }

  verifyHeaders({ authorization = '' }: IncomingHttpHeaders): Promise<any> {
    const [protocol, token] = authorization.split(' ');
    if (protocol === 'Bearer' && token) return this.verifyToken(token);
    throw new UnauthorizedException();
  }

  async verifyToken(token: string): Promise<any> {
    try {
      return await this.cognitoExpress.validate(token);
    } catch (err) {
      console.log(err.message, err.stack);
    }
  }

  async signInCognito(email: string, password: string) {
    const { AuthenticationResult } = await this.cognitoIdentityServiceProvider
      .adminInitiateAuth({
        UserPoolId: this.cognito.COGNITO_USER_POOL_ID as string,
        ClientId: this.cognito.COGNITO_CLIENT_ID as string,
        AuthFlow: 'ADMIN_NO_SRP_AUTH',
        AuthParameters: {
          USERNAME: email,
          PASSWORD: password,
        },
      })
      .promise();
    return AuthenticationResult;
  }

  async signOutCognito(Username: string) {
    await this.cognitoIdentityServiceProvider.adminUserGlobalSignOut(
      {
        UserPoolId: this.cognito.COGNITO_USER_POOL_ID as string,
        Username: Username /* required */,
      },
      function (err, data) {
        if (err) console.log(err, err.stack); // an error occurred
        else console.log(data); // successful response
      }
    );
  }
}
