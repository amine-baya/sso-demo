const express = require('express');
const app = express();
const saml = require('samlify');
const validator = require('@authenio/samlify-xsd-schema-validator');
const fs = require('fs');


app.use(express.json());
saml.setSchemaValidator(validator);

const spRouter = new express.Router();

const idpRouter = new express.Router();

const sp = saml.ServiceProvider({
	metadata: fs.readFileSync('./metadata/metadata-sp.xml'),
	privateKey: fs.readFileSync('./certs/sp/key'),
	privateKeyPass: 'test',
	signingCert: fs.readFileSync('./certs/sp/cert'),
	requestSignatureAlgorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512',
});

const idp = saml.IdentityProvider({
	metadata: fs.readFileSync('./metadata/metadata-idp.xml'),
	privateKey: fs.readFileSync('./certs/idp/key'),
	privateKeyPass: 'test',
	signingCert: fs.readFileSync('./certs/idp/cert'),
	loginResponseTemplate: {
		context: fs.readFileSync('./src/response.xml'),
		attributes: [
		      { name: "fullname", valueTag: "user.name", nameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic", valueXsiType: "xs:string" },
		      { name: "email", valueTag: "user.email", nameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic", valueXsiType: "xs:string" },
		      { name: "eppn", valueTag: "user.id", nameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic", valueXsiType: "xs:string" }
		],
	
	}
});

// parse when we receive a SAML response from an IdP
spRouter.post('/acs', (req, res) => {
	sp.parseLoginResponse(idp, 'post', req)
		.then(parseResult => {
			console.log('authentication response', parseResult);
			res.send(parseResult);
		})
		.catch(err => {
			console.log('authentication response error', err);
			res.status(500).send(err);
		});
});

spRouter.get('/initiate', (req, res) => {
	const { context } = sp.createLoginRequest(idp, 'redirect');
	res.redirect(context);
});
const buildOctetStringFromQuery = (query={}) => {
    return Object.keys(query)
        .filter(param => param !== "Signature")
        .map(param => param + "=" + encodeURIComponent(query[param]))
        .join("&");
}

app.use('/sp', spRouter);

idpRouter.get('/redirect', (req, res) => {
	console.log("this is the idp redirect");
	req.octetString = buildOctetStringFromQuery(req.query);
	idp.parseLoginRequest(sp, 'redirect', req)
		.then(parseResult => {
			const user = {
				id: '123',
				email: '123@mail.com',
				fullname: 'John Doe',
				eppn: 'some id',
				name: 'testing'
			};

			parseResult.attributes = user;
			const replacement = (template) => {
				return template.toString();
			}

			return idp.createLoginResponse(sp, parseResult, 'post', user, replacement , true);
		}).then(loginResponse => {
			loginResponse.SAMLResponse = loginResponse.context;
			delete loginResponse.context;
			loginResponse.relayState = "";
			console.log("IDP SUCCESS", JSON.stringify(loginResponse));
		})
		.catch(err => {
			console.error('parseError', err);
		});
	res.send("this is the idp redirect");
});

app.use('/idp', idpRouter);

app.listen(3000, () => {
	console.log('Example app listening on port 3000!');
});
