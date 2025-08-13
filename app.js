const ejs = require('ejs');
const express = require('express')
const app = express()

const bodyparser = require('body-parser');
const urlencodedparser = bodyparser.urlencoded({
  extended: false
})

const pg = require("pg")
const Pool = pg.Pool;

const session = require('express-session')
const pgSession = require('connect-pg-simple')(session)
const passport = require('passport')
const GoogleStrategy = require('passport-google-oauth2').Strategy;


const {
  google
} = require('googleapis');


const cron = require('node-cron');

const GOOGLE_CLIENT_ID = "186847478086-o0q54g444i450f7od5e994lcr8n06ffn.apps.googleusercontent.com"
const GOOGLE_CLIENT_SECRET = "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"
const GOOGLE_REDIRECT_URI = "http://sviluppo.arstca.it:3000/auth/google/callback"

const SCOPES = ["email", "profile",
  "https://www.googleapis.com/auth/documents ",
  "https://www.googleapis.com/auth/drive",
  "https://www.googleapis.com/auth/drive.file",
  "https://www.googleapis.com/auth/drive.resource",
  'https://www.googleapis.com/auth/spreadsheets'
];


function authorize(request, callback, ...params) {
  const oAuth2Client = new google.auth.OAuth2(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI);
  let sess=request.session;
  console.log(sess);
  oAuth2Client.setCredentials(sess.passport.user.GOOGLE_API_TOKEN);
  return callback(oAuth2Client, ...params);
}

async function generateDocFromTemplate(auth, owner, templateId, templateTitle, docNumber, mezzoFolderId, mapping) {
  
  let copiedDocumentId = null;

  const docs = google.docs({
    version: 'v1',
    auth
  });
  const drive = google.drive({
    version: "v3",
    auth
  });

  const currentYear = new Date().getFullYear();

  let destinationFolderId = null;
  try {
    console.log("destinationFolder",'\''+mezzoFolderId+'\' in parents and name=\''+currentYear+'\'');
    const res = await drive.files.list({
      q: '\''+mezzoFolderId+'\' in parents and name=\''+currentYear+'\''
    });
    console.debug(res);
    if (res.data.files && res.data.files.length == 1){
      destinationFolderId = res.data.files[0].id;
      console.debug("destinationFolderId trovata",destinationFolderId);
    } else {
      //se non trovo la sottocartella la creo
      const fileMetadata = {
        name: currentYear,
        mimeType: 'application/vnd.google-apps.folder',
        parents: [mezzoFolderId]
      };
      const resCreate = await drive.files.create({
        resource: fileMetadata,
        fields: 'id'
      });
      console.log("resCreatete.data",resCreate.data);
      destinationFolderId = resCreate.data.id;
      console.debug("destinationFolderId creata",destinationFolderId);
    }
  } catch (err) {
    console.error("errore nella lista: "+ err);
  }

  const normalizeText = function(text){
    text = text.replace("&#39;","'");
    return text;
  }
  const getReplaceItem = function(key, value){
    return {
      "replaceAllText": {
        "containsText": {
          "text": "{{" + key + "}}",
          "matchCase": true,
        },
        "replaceText": normalizeText(value),
      }
    };
  }

  const requests = Object.entries(JSON.parse(mapping)).map( ([key, value]) => {
    return getReplaceItem(key, value);
  });

  //copia da template
  const copyRequest = {
    name: formatDateFolder(new Date()) + "_" + ("0000" + docNumber).slice(-5) + "_" + templateTitle, 
    parents: [destinationFolderId]
  };
  console.debug("templateTitle",templateTitle)
  try {
    const resCopy = await drive.files.copy({
      fileId: templateId,
      resource: copyRequest
    });
    console.log("resCopy.data",resCopy.data);

    if (resCopy.data){
      copiedDocumentId = resCopy.data.id;
      console.log("copiedDocumentId", copiedDocumentId);

      //sostituzione massiva
      docs.documents.batchUpdate({
        documentId: copiedDocumentId,
        resource: {
          requests
        },
      });

      //trasferimento proprietà documento
      drive.permissions.create({
        fileId: copiedDocumentId,
        transferOwnership: 'true',
        resource: {
          role: 'owner',
          type: 'user',
          emailAddress: owner
        }
      });

    }
  } catch (err) {
    console.error("errore nella copia:" + err)
  }

  return copiedDocumentId;

}

/*
async function exportToSheetAsync(auth, data){
  const sheets = google.sheets({
    version: 'v4', 
    auth
  });
  const drive = google.drive({
    version: "v3",
    auth
  });

  const createOption = {
    resource: {
      properties: {
        title: 'Export mezzi ' + formatDateTime(new Date())
      }
    }
  };
 
  let sheetId = null;
  sheets.spreadsheets.create(createOption, function (err, response) {
    if (err) {
      console.error(err);
      return;
    }
  
    sheetId = response.data.spreadsheetId;

    const driveMoveOption = {
      fileId: sheetId,
      addParents: "1jXAXsgfuUrbCGUMXBJFV4Xr_5bwzbDtr",
      removeParents: "root"
    }

    drive.files.update(driveMoveOption, function (err, response) {
      if (err) {
        console.error(err);
        return;
      }
      sheets.spreadsheets.values.append(
        {
          spreadsheetId: sheetId,
          range: 'Foglio1',
          valueInputOption: 'RAW',
          insertDataOption: 'INSERT_ROWS',
          resource: { 
            values: data
          },
          auth: auth,
        },
        (err, result) => {
          if (err) {
            console.log(err);
          } else {
            console.log(
              '%d cells updated on range: %s',
              result.data.updates.updatedCells,
              result.data.updates.updatedRange
            );
          }
        }
      );
    });
  });
}
*/

async function exportToSheet(auth, data){
  const sheets = google.sheets({
    version: 'v4', 
    auth
  });
  const drive = google.drive({
    version: "v3",
    auth
  });

  const createOption = {
    resource: {
      properties: {
        title: 'Export mezzi ' + formatDateTime(new Date())
      }
    }
  };
 
  let responseCreate = await sheets.spreadsheets.create(createOption);
  let sheetId = responseCreate.data.spreadsheetId;

  const driveMoveOption = {
    fileId: sheetId,
    addParents: "1jXAXsgfuUrbCGUMXBJFV4Xr_5bwzbDtr",
    removeParents: "root"
  }
  await drive.files.update(driveMoveOption);

  const appendOptions = {
    spreadsheetId: sheetId,
    range: 'Foglio1',
    valueInputOption: 'RAW',
    insertDataOption: 'INSERT_ROWS',
    resource: { 
      values: data
    },
    auth: auth
  };
  await sheets.spreadsheets.values.append(appendOptions);

  return sheetId;

}

const pool = new Pool({
  user: "gtfsownr",
  host: "127.0.0.1", //"192.168.10.200",
  database: "manutenzioni",
  password: "gtfsownr",
  port: 5432
});

app.use(session({
  store: new pgSession({
    pool: pool,
    tableName: 'session'
  }),
  secret: "secret",
  resave: false,
  cookie: { maxAge: 30 * 24 * 60 * 60 * 1000 },
  saveUninitialized: true,
}))

app.use(passport.initialize())
app.use(passport.session())


let logLevels = ["debug", "info", "error", "none"];
let shouldLog = (level) => {
  return logLevels.indexOf(level) >= logLevels.indexOf(global.logLevel);
};


global.logLevel = "debug";
let _console = console
global.console = {
  ...global.console,
  info: (message, ...optionalParams) => {
    shouldLog("info") && _console.info(message, ...optionalParams);
  },
  error: (message, ...optionalParams) => {
    shouldLog("error") && _console.error(message, ...optionalParams);
  },
  debug: (message, ...optionalParams) => {
    shouldLog("debug") && _console.debug(message, ...optionalParams);
  },
};


authUser = (request, accessToken, refreshToken, profile, done) => {
  console.debug("######### accessToken", accessToken);
  console.debug("######### refreshToken", refreshToken);
  profile.GOOGLE_API_TOKEN = {
    "status": "approved",
    "refresh_token": refreshToken,
    "access_token": accessToken
  };
  return done(null, profile);
}


passport.use(new GoogleStrategy({
  clientID: GOOGLE_CLIENT_ID,
  clientSecret: GOOGLE_CLIENT_SECRET,
  callbackURL: "http://sviluppo.arstca.it:3000/auth/google/callback",
  passReqToCallback: true
}, authUser));


passport.serializeUser((user, done) => {
  console.info("BEGIN serializeUser");
  // salva lo user in "req.session.passport.user.{user}" 
  let ruoli = [];
  let sedi = [];
  pool.query(
    "SELECT * FROM v_utenti_ruoli where mail = $1",
    [user.email],
    (error, resultsRuoli) => {
      if (error) {
        console.error(error);
        done(null, user)
        console.info("END serializeUser");
      } else {
        if (resultsRuoli.rows && resultsRuoli.rows.length > 0) {
          for (let i = 0; i < resultsRuoli.rows.length; i++) {
            ruolo = resultsRuoli.rows[i].codice_ruolo;
            ruoli.push(ruolo);
          }
        }
        pool.query(
          "SELECT * FROM v_utenti_sedi where mail = $1",
          [user.email],
          (error, resultsSedi) => {

            if (error) {
              console.error(error);
              done(null, user)
              console.info("END serializeUser");
            } else {
              if (resultsSedi.rows && resultsSedi.rows.length > 0) {
                for (let i = 0; i < resultsSedi.rows.length; i++) {
                  sede = resultsSedi.rows[i].codice_sede;
                  if (sede != null){
                    sedi.push(sede);
                  } 
                }
              }
              user.sedi = sedi;
              user.ruoli = ruoli;
              //console.debug(user);
              done(null, user)
              console.info("END serializeUser");
            }
          }
        );
      }
    }
  );
})


passport.deserializeUser((user, done) => {
  //salva lo user in "req.user.{user}", in modo che possa essere richiamato
  console.info("BEGIN deserializeUser");
  done(null, user)
  console.info("END deserializeUser");
})



app.listen(3000, () => console.debug(`Server started on port 3000...`))


showlogs = (req, res, next) => {
  /*
  console.debug(req.session.passport)
  console.debug(req.user)
  console.debug(req.session.id)
  console.debug(req.session.cookie)
  */
  next()
}

app.use(showlogs)

app.use(express.static("public"))

authorizeAPI = (req, res, next) => {
  if (req.url.startsWith("/api/")){
    if(authorizeAPIByRole(req)){
      next()
    } else {
      console.log("#########" + req.method + " " + (req.url) + " UNAUTHORIZED")
      res.status(401).end();
      return;
    }
  } else {
    next()
  }
}

authorizeAPIByRole = (req) => {
  if (req.user && req.user.ruoli){
    const method = req.method;
    const url = req.url;
    const roles = req.user.ruoli;
    return checkAuthorization(method, url, roles)
  } else {
    return false;
  }
}

const authorizationRules = [
  {
    url: "/api/v1/test",
    method: "GET",
    roles: ["ADMIN","ES","FSM","FEM","FGMF"]
  },
  {
    url: "/api/v1/mezzi",
    method: "GET",
    roles: ["ADMIN","ES","FSM","FEM","FGMF"]
  },
  {
    url: "/api/v1/mezzi/:id",
    method: "GET",
    roles: ["ADMIN","ES","FSM","FEM","FGMF"]
  },
  {
    url: "/api/v1/stati",
    method: "GET",
    roles: ["ADMIN","ES","FSM","FEM","FGMF"]
  },
  {
    url: "/api/v1/tipicomunicazione",
    method: "GET",
    roles: ["ADMIN","ES","FSM","FEM","FGMF"]
  },
  {
    url: "/api/v1/tipicomunicazione/all",
    method: "GET",
    roles: ["ADMIN","ES","FSM","FEM","FGMF"]
  },
  {
    url: "/api/v1/tipisegnalazione",
    method: "GET",
    roles: ["ADMIN","ES","FSM","FEM","FGMF"]
  },
  {
    url: "/api/v1/tipimanutenzione",
    method: "GET",
    roles: ["ADMIN","ES","FSM","FEM","FGMF"]
  },
  {
    url: "/api/v1/interventimanutenzione/datatable",
    method: "GET",
    roles: ["ADMIN","ES","FSM","FEM","FGMF"]
  },



  {
    url: "/api/v1/mezzi/datatable",
    method: "GET",
    roles: ["ADMIN","ES","FSM","FEM","FGMF"]
  },
  {
    url: "/api/v1/mezzi/export",
    method: "GET",
    roles: ["ADMIN","ES","FSM","FEM","FGMF"]
  },
  {
    url: "/api/v1/registrazioni",
    method: "POST",
    roles: ["ADMIN","ES","FSM"]
  },
{
    url: "/api/v1/statimezzo",
    method: "POST",
    roles: ["ADMIN","FSM","FEM","FGMF"]
  },
{
    url: "",
    method: "",
    roles: ["ADMIN","FSM","FEM","FGMF"]
  },
{
    url: "/api/v1/manutenzioni",
    method: "GET",
    roles: ["ADMIN","ES","FSM","FEM","FGMF"]
  },
  {
    url: "/api/v1/manutenzioni/:id",
    method: "GET",
    roles: ["ADMIN","FSM","FEM","FGMF"]
  },
  {
    url: "/api/v1/manutenzioni/datatable",
    method: "GET",
    roles: ["ADMIN","ES","FSM","FEM","FGMF"]
  },
{
    url: "/api/v1/manutenzioni",
    method: "POST",
    roles: ["ADMIN","FSM","FEM","FGMF"]
  },
{
    url: "/api/v1/manutenzioni/:id",
    method: "PUT",
    roles: ["ADMIN","FSM","FEM","FGMF"]
  },
{
    url: "/api/v1/manutenzioni/:id",
    method: "DELETE",
    roles: ["ADMIN","FSM","FEM","FGMF"]
  },
  {
    url: "/api/v1/segnalazioni/:id",
    method: "GET",
    roles: ["ADMIN","ES","FSM","FEM","FGMF"]
  },
{
  url: "/api/v1/segnalazioni/datatable",
  method: "GET",
  roles: ["ADMIN","ES","FSM","FEM","FGMF"]
},
{
    url: "/api/v1/segnalazioni",
    method: "GET",
    roles: ["ADMIN","ES","FSM","FEM","FGMF"]
  },
{
    url: "/api/v1/segnalazioni",
    method: "POST",
    roles: ["ADMIN","ES","FSM"]
  },
{
    url: "/api/v1/segnalazioni/:id",
    method: "PUT",
    roles: ["ADMIN","ES","FSM"]
  },
{
    url: "/api/v1/segnalazioni/:id",
    method: "PATCH",
    roles: ["ADMIN","FSM","FEM","FGMF"]
  },
{
    url: "/api/v1/segnalazioni/:id",
    method: "DELETE",
    roles: ["ADMIN","ES","FSM"]
  },
{
    url: "/api/v1/comunicazioni",
    method: "GET",
    roles: ["ADMIN","ES","FSM","FEM","FGMF"]
  },
{
    url: "/api/v1/comunicazioni/:id",
    method: "GET",
    roles: ["ADMIN","ES","FSM","FEM","FGMF"]
  },
{
    url: "/api/v1/comunicazioni/datatable",
    method: "GET",
    roles: ["ADMIN","ES","FSM","FEM","FGMF"]
  },
{
    url: "/api/v1/comunicazioni",
    method: "POST",
    roles: ["ADMIN","ES","FSM","FEM","FGMF"]
  },
{
    url: "/api/v1/comunicazioni/:id",
    method: "PUT",
    roles: ["ADMIN","ES","FSM","FEM","FGMF"]
  },
{
    url: "/api/v1/comunicazioni/:id",
    method: "DELETE",
    roles: ["ADMIN","ES","FSM","FEM","FGMF"]
  },
];

checkAuthorization = (method, url, roles) => {
  let match = false;

  if (url.indexOf("?") != -1){
    url = url.split("?");
    url = url[0];
  }
  

  for(let i = 0; i < authorizationRules.length; i++){
    const rule = authorizationRules[i];
    let tempUrl = url;
    if(rule.url.indexOf(":id") != -1){
      tempUrl = tempUrl.split("/");
      tempUrl.pop();
      tempUrl = tempUrl.join("/");
      tempUrl = tempUrl +"/";
    }
    if(tempUrl == rule.url.replace("/:id","/") && method == rule.method && rolesMatches(roles, rule.roles)){
      match = true;
      break;
    }
  }
  return match;
}

app.use(authorizeAPI)

const rolesMatches = function(roles1,roles2){
  return roles1.some(element => {
    return roles2.includes(element);
  });
}

app.get('/auth/google',
  passport.authenticate('google', {
    scope: SCOPES
  })
);

app.get('/auth/google/callback',
  passport.authenticate('google', {
    successRedirect: '/mezzi',
    failureRedirect: '/login'
  })
);


checkAuthenticated = (req, res, next) => {
  console.info("BEGIN checkAuthenticated")
  if (req.isAuthenticated()) {
    console.debug("Utente autenticato su Google")
    if (req.user.ruoli.length > 0) {
      console.debug("L'utente ha ruoli applicativi. Accesso consentito")
      console.info("END checkAuthenticated")
      return next()
    } else {
      console.debug("L'utente non ha ruoli applicativi. Accesso negato")
      console.info("END checkAuthenticated")
      res.redirect("/unauthorized");
    }
  } else {
    console.info("END checkAuthenticated")
    res.redirect("/login")
  }

}

//TEST
const test = function(user){
  const mezzo = {
    id: "ferC01",
  }
  mapping = {
    "nome": "<%= user.given_name %>",
    "cognome": "<%= user.family_name %>",
    "mezzo": "<%= mezzo.id %>"
  }
  mapping = ejs.render(JSON.stringify(mapping), {user: user, mezzo: mezzo});
  console.log(mapping);
}


app.get("/login", (req, res) => {
  console.info("BEGIN get /login")
  res.render("login.ejs")
  console.info("END get /login")
})

app.get("/logout", (req, res) => {
  console.info("BEGIN get /logout")
  req.logout(req, err => {
    if (err) {
      return next(err);
    }
    req.session = null;
    res.redirect("/login");
  });
})

app.get("/unauthorized", (req, res) => {
  console.info("BEGIN get /unauthorized")
  res.render("unauthorized.ejs", {
    user: req.user
  })
  console.info("END get /unauthorized")
})

app.get("/mezzi", checkAuthenticated, (req, res) => {
  console.info("BEGIN get /mezzi")
  res.render("mezzi.ejs", {
    user: req.user,
    page: "MEZZI"
  })
  console.info("END get /mezzi")
})

app.get("/interventimanutenzione", checkAuthenticated, (req, res) => {
  console.info("BEGIN get /interventimanutenzione")
  res.render("interventi_manutenzione.ejs", {
    user: req.user,
    page: "PRONTUARIO"
  })
  console.info("END get /interventimanutenzione")
})

app.get("/manutenzioni", checkAuthenticated, (req, res) => {
  console.info("BEGIN get /manutenzioni")
  res.render("manutenzioni.ejs", {
    user: req.user,
    page: "MANUTENZIONI"
  })
  console.info("END get /manutenzioni")
})

app.get("/segnalazioni", checkAuthenticated, (req, res) => {
  console.info("BEGIN get /segnalazioni")
  res.render("segnalazioni.ejs", {
    user: req.user,
    page: "SEGNALAZIONI"
  })
  console.info("END get /segnalazioni")
})

app.get("/comunicazioni", checkAuthenticated, (req, res) => {
  console.info("BEGIN get /comunicazioni")
  res.render("comunicazioni.ejs", {
    user: req.user,
    page: "COMUNICAZIONI"
  })
  console.info("BEGIN get /comunicazioni")
})

//MEZZI START
app.get("/api/v1/mezzi/", (req, res) => {
  console.info("BEGIN get /api/v1/mezzi/")
  pool.query(

    "SELECT * FROM v_mezzi order by codice_mezzo",
    (error, results) => {
      if (error) {
        console.error(error);
        res.status(500).json({
          error: 'Errore imprevisto'
        });
      } else {
        //filtro dati per sede
        if (req.user.sedi.length > 0){
          console.log(req.user.sedi);
          let sede = req.user.sedi[0];
          results.rows = results.rows.filter( s => s.codice_sede == sede)
        }
        res.status(200).json(results.rows);
      }
      console.info("END get /api/v1/mezzi/")
    }
  );
});

app.get("/api/v1/mezzi/datatable", (req, res) => {
  console.info("BEGIN get /api/v1/mezzi/datatable")
  const q = req.query.q

  pool.query(

    "SELECT * FROM v_mezzi order by descrizione_sede, codice_mezzo",
    (error, results) => {
      if (error) {
        console.error(error);
        res.status(500).json({
          error: 'Errore imprevisto'
        });
      } else {
        let mezzi = {}
        mezzi.data = results.rows
        //filtro dati per sede
        if (req.user.sedi.length > 0){
          console.log(req.user.sedi);
          let sede = req.user.sedi[0];
          mezzi.data = mezzi.data.filter( s => s.codice_sede == sede)
        }
        res.status(200).json(mezzi);
      }
      console.info("END get /api/v1/mezzi/datatable")
    }
  );
});

app.get('/api/v1/mezzi/export', urlencodedparser, async (req, res) => { //async (req, res) 
  const sql = `SELECT codice_sede, descrizione_tipo_mezzo, descrizione_costruttore, descrizione_direzione, descrizione_tipo_trazione, descrizione_stato,	note_stato,
  codice_mezzo, descrizione_mezzo, flag_trazione, caratteristiche_particolari, n_cabine_pilotaggio, n_posti_a_sedere, n_posti_a_sedere_altri,
  anno_costruzione, anno_messa_esercizio, codice_tipo_alert, dettagli_alert, dettagli_segnalazione, id_fascicolo,
  km, km_vita, descrizione_tipo_comunicazione FROM v_mezzi order by descrizione_sede, codice_mezzo`;
  const results = await pool.query(sql);
  if (results.rows && results.rows.length > 0 ){
    let data = results.rows
    //filtro dati per sede
    if (req.user.sedi.length > 0){
      console.log(req.user.sedi);
      let sede = req.user.sedi[0];
      data = data.filter( s => s.codice_sede == sede)
    }
    const exportData = convertAssociativeArrayToArray(data); 
    const sheetId = await authorize(req, exportToSheet, exportData); 
    let ret = {};
    ret.sheetId = sheetId;
    res.status(200).json(ret);
  } else {
    let ret = {};
    ret.sheetId = null;
    res.status(200).json(ret);

  }



  /*
  pool.query(

    "SELECT * FROM v_mezzi order by descrizione_sede, codice_mezzo",
    (error, results) => {
      if (error) {
        console.error(error);
        res.status(500).json({
          error: 'Errore imprevisto'
        });
      } else {
        let mezzi = {}
        data = results.rows
        //filtro dati per sede
        if (req.user.sedi.length > 0){
          console.log(req.user.sedi);
          let sede = req.user.sedi[0];
          data = data.filter( s => s.codice_sede == sede)
        }
        const exportData = convertAssociativeArrayToArray(data); 
        const sheetId = await authorize(req, exportToSheet, exportData); 
        let ret = {};
        ret.sheetId = sheetId;
        res.status(200).json(ret);
      }
      console.info("END get /api/v1/mezzi/datatable")
    }
  ); */
  
});

app.get("/api/v1/mezzi/:id", (req, res) => {
  console.info("BEGIN get api /api/v1/mezzi/:id")
  const id = req.params.id

  pool.query(
    "SELECT * FROM v_mezzi WHERE id_mezzo = $1",
    [id],
    (error, results) => {
      if (error) {
        console.error(error);
        res.status(500).json({
          error: 'Errore imprevisto'
        });
      } else {
        if (results.rows && results.rows.length == 1) {
          res.status(200).json(results.rows[0]);
        } else {
          res.status(404).json({
            error: 'Mezzo non trovato'
          });
        }
      }
      console.info("END get api /api/v1/mezzi/:id")
    }
  );
});

app.post('/api/v1/registrazioni', urlencodedparser, (req, res) => {
  console.info("BEGIN post api /api/v1/registrazioni")
  const registrazione = req.body;

  pool.query(
    "UPDATE registrazioni set corrente = FALSE, mod_data = now(), mod_user = $4 where id_mezzo = $1 and id_tipo_registrazione = $2 and id_tipo_manutenzione = $3",
    [registrazione.idMezzo, registrazione.idTipoRegistrazione, registrazione.idTipoManutenzione, req.user.email],
    (error, results) => {
      if (error) {
        console.error(error)
        res.status(500).json({
          error: 'Errore imprevisto'
        });
      } else {
        pool.query(
          "INSERT INTO registrazioni (id_mezzo, id_tipo_registrazione, data, km, km_vita, id_tipo_manutenzione, correttiva, note, corrente, ins_user) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, true, $9)",
          [registrazione.idMezzo, registrazione.idTipoRegistrazione, registrazione.data, registrazione.km, registrazione.kmVita, registrazione.idTipoManutenzione, registrazione.correttiva, registrazione.note, req.user.email],
          (error, results) => {
            if (error) {
              console.error(error);
              res.status(500).json({
                error: 'Errore imprevisto'
              });
            }
            calculateVehicleDeadline(registrazione.idMezzo);
            getVehicleFaultReporting(registrazione.idMezzo);
            res.status(201).end();
          }
        );
      }
      console.info("END post api /api/v1/registrazioni")
    }
  );
});

app.get("/api/v1/stati", (req, res) => {
  console.info("BEGIN get api /api/v1/stati")
  pool.query(
    "SELECT * FROM stati",
    (error, results) => {
      if (error) {
        console.error(error);
        res.status(500).json({
          error: 'Errore imprevisto'
        });
      } else {
        if (results.rows && results.rows.length > 0) {
          res.status(200).json(results.rows);
        } else {
          res.status(404).json({
            error: 'Stati non trovati'
          });
        }
      }
      console.info("END get api /api/v1/stati")
    }
  );
});

app.post('/api/v1/statimezzo', urlencodedparser, (req, res) => {
  console.info("BEGIN post /api/v1/statimezzo")
  const registrazione = req.body;

  pool.query(
    "UPDATE rel_mezzi_stati set data_fine = NOW() where id_mezzo = $1",
    [registrazione.idMezzo],
    (error, results) => {
      if (error) {
        console.error(error)
        res.status(500).json({
          error: 'Errore imprevisto'
        });
      } else {
        pool.query(
          "INSERT INTO rel_mezzi_stati (id_stato, id_mezzo, data_inizio, note, ins_user) VALUES ($1, $2, $3, $4, $5)",
          [registrazione.idStato, registrazione.idMezzo, registrazione.data, registrazione.note, req.user.email],
          (error, results) => {
            if (error) {
              console.error(error);
              res.status(500).json({
                error: 'Errore imprevisto'
              });
            } else {
              res.status(201).end();
            }
          }
        );
      }
      console.info("END post /api/v1/statimezzo")
    }
  );
});
//MEZZI END


//DETTAGLI MANUTENZIONI START
app.get("/api/v1/interventimanutenzione/datatable", (req, res) => {
  console.info("BEGIN get /api/v1/dettaglitipimanutenzione/datatable")
  //const q = req.query.q;
  pool.query(
    "SELECT *  FROM v_dettagli_manutenzione",
    (error, results) => {
      if (error) {
        console.error(error)
        res.status(500).json({
          error: 'Errore imprevisto'
        });
      } else {
        let dettagli = {}
        dettagli.data = results.rows
        /* //filtro per sede
        if (req.user.sedi.length > 0){
          console.log(req.user.sedi);
          let sede = req.user.sedi[0];
          dettagli.data = dettagli.data.filter( s => s.codice_sede == sede)
        }
        */
        res.status(200).json(dettagli);
      }
      console.info("END get /api/v1/dettaglitipimanutenzione/datatable")
    }
  );
});
//DETTAGLI MANUTENZIONI END

//MANUTENZIONI START
app.get("/api/v1/tipimanutenzione", (req, res) => {
  console.info("BEGIN get /api/v1/tipimanutenzione")
  const idMezzo = req.query.idMezzo;
  pool.query(
    "SELECT * FROM v_tipi_manutenzione WHERE id_mezzo = $1 ORDER BY codice_tipo_manutenzione", [idMezzo],
    (error, results) => {
      if (error) {
        console.error(error);
        res.status(500).json({
          error: 'Errore imprevisto'
        });
      } else {
        if (results.rows && results.rows.length > 0) {
          res.status(200).json(results.rows);
        } else {
          res.status(404).json({
            error: 'Tipi di manutenzione non trovate per il mezzo selezionato'
          });
        }
      }
      console.info("END get /api/v1/tipimanutenzione")
    }
  );
});

app.get("/api/v1/manutenzioni/", (req, res) => {
  console.info("BEGIN get /api/v1/manutenzioni/")
  //const q = req.query.q;
  pool.query(
    "SELECT * FROM v_manutenzioni order by descrizione_sede, codice_mezzo",
    (error, results) => {
      if (error) {
        console.error(error);
        res.status(500).json({
          error: 'Errore imprevisto'
        });
      } else {
        res.status(200).json(results.rows);
      }
    }
  );
  console.info("END get /api/v1/manutenzioni/")
});

app.get("/api/v1/manutenzioni/datatable", (req, res) => {
  console.info("BEGIN get /api/v1/manutenzioni/datatable")
  //const q = req.query.q;
  pool.query(
    "SELECT codice_mezzo, descrizione_costruttore, codice_sede, descrizione_sede, codice_tipo_manutenzione, data, km, id_manutenzione  FROM v_manutenzioni where eliminato = false order by descrizione_sede, codice_mezzo",
    (error, results) => {
      if (error) {
        console.error(error)
        res.status(500).json({
          error: 'Errore imprevisto'
        });
      } else {
        let manutenzioni = {}
        manutenzioni.data = results.rows
        //filtro dati per sede
        if (req.user.sedi.length > 0){
          console.log(req.user.sedi);
          let sede = req.user.sedi[0];
          manutenzioni.data = manutenzioni.data.filter( s => s.codice_sede == sede)
        }
        res.status(200).json(manutenzioni);
      }
      console.info("END get /api/v1/manutenzioni/datatable")
    }
  );
});

app.get("/api/v1/manutenzioni/:id", (req, res) => {
  console.info("BEGIN get /api/v1/manutenzioni/:id")
  const id = req.params.id

  pool.query(
    "SELECT * FROM v_manutenzioni WHERE id_manutenzione = $1",
    [id],
    (error, results) => {
      if (error) {
        console.error(error)
        res.status(500).json({
          error: 'Errore imprevisto'
        });
      } else {
        if (results.rows && results.rows.length == 1) {
          res.status(200).json(results.rows[0]);
        } else {
          res.status(404).json({
            error: 'Manutenzione non trovata'
          });
        }
      }
      console.info("END get /api/v1/manutenzioni/:id")
    }
  );
});

app.delete("/api/v1/manutenzioni/:id", (req, res) => {
  console.info("BEGIN delete /api/v1/manutenzioni/:id")
  const id = req.params.id

  pool.query(
    "select * from manutenzioni WHERE id_manutenzione = $1 and corrente = true",
    [id],
    (error, results) => {
      if (error) {
        console.error(error)
        res.status(500).json({
          error: 'Errore imprevisto'
        }).end();
      } else {
        if (results.rows && results.rows.length == 1) {
          manutenzione = results.rows[0];
          //cerco la manutenzione precedente e la attivo
          pool.query(
            "UPDATE manutenzioni set eliminato = true, corrente = false, mod_data = now(), mod_user = $2 WHERE id_manutenzione = $1",
            [id, req.user.email],
            (error, results) => {
              if (error) {
                console.error(error)
                res.status(500).json({
                  error: 'Errore imprevisto'
                }).end();
              }
              pool.query(
                "update manutenzioni set corrente = true where id_manutenzione = (select max(id_manutenzione) from manutenzioni WHERE id_mezzo = $1 AND id_tipo_manutenzione = $2 and eliminato = false)",
                [manutenzione.id_mezzo, manutenzione.id_tipo_manutenzione],
                (error, results) => {
                  if (error) {
                    console.error(error)
                    res.status(500).json({
                      error: 'Errore imprevisto'
                    }).end();
                  }
                  calculateVehicleDeadline(manutenzione.id_mezzo)
                  res.status(204).end();
                }
              );
            }
          );
        } else {
          console.debug('Non è possibile eliminare una manutenzione passata; eliminare prima tutte le manutenzioni successive');
          res.status(500).json({
            error: 'Non è possibile eliminare una manutenzione passata; eliminare prima tutte le manutenzioni successive'
          }).end();
        }
      }
      console.info("END delete /api/v1/manutenzioni/:id")
    }
  );
});

app.post('/api/v1/manutenzioni', urlencodedparser, (req, res) => {
  console.info("BEGIN post /api/v1/manutenzioni")
  const manutenzione = req.body;

  pool.query(
    "UPDATE manutenzioni set corrente = FALSE, mod_data = now(), mod_user = $3 where id_mezzo = $1 AND id_tipo_manutenzione = $2",
    [manutenzione.idMezzo, manutenzione.idTipoManutenzione, req.user.email],
    (error, results) => {
      if (error) {
        console.error(error)
        res.status(500).json({
          error: 'Errore imprevisto'
        });
      } else {
        pool.query(
          "INSERT INTO manutenzioni (id_mezzo, id_segnalazione, data, km, id_tipo_manutenzione, correttiva, note, corrente, ins_user) VALUES ($1, $2, $3, $4, $5, $6, $7, true, $8)",
          [manutenzione.idMezzo, manutenzione.idSegnalazione, manutenzione.data, manutenzione.km, manutenzione.idTipoManutenzione, manutenzione.correttiva, manutenzione.note, req.user.email],
          (error, results) => {
            if (error) {
              console.error(error)
              res.status(500).json({
                error: 'Errore imprevisto'
              });
            }
            if (manutenzione.idSegnalazione != 0) {
              pool.query(
                "UPDATE segnalazioni set aperta = FALSE, mod_data = now(), mod_user = $2 WHERE id_segnalazione = $1",
                [manutenzione.idSegnalazione, req.user.email],
                (error, results) => {
                  if (error) {
                    console.error(error)
                    res.status(500).json({
                      error: 'Errore imprevisto'
                    });
                  }
                  calculateVehicleDeadline(manutenzione.idMezzo)
                  getVehicleFaultReporting(manutenzione.idMezzo);
                  res.status(201).end();
                }
              );
            } else {
              calculateVehicleDeadline(manutenzione.idMezzo)
              res.status(201).end();
            }
          }
        );
      }
      console.info("END post /api/v1/manutenzioni")
    }
  );
});

app.put('/api/v1/manutenzioni', urlencodedparser, (req, res) => {
  console.info("BEGIN put /api/v1/manutenzioni")
  const manutenzione = req.body;

  pool.query(
    "UPDATE manutenzioni set data = $1, km = $2, id_tipo_manutenzione = $3, correttiva = $4, note = $5, mod_data = now(), mod_user = $7 WHERE id_manutenzione = $6",
    [manutenzione.data, manutenzione.km, manutenzione.idTipoManutenzione, manutenzione.correttiva, manutenzione.note, manutenzione.idManutenzione, req.user.email],
    (error, results) => {
      if (error) {
        console.error(error)
        res.status(500).json({
          error: 'Errore imprevisto'
        });
      } else {
        res.status(204).end();
      }
      console.info("END put /api/v1/manutenzioni")
    }
  );

});
//MANUTENZIONI END

//SEGNALAZIONI BEGIN
app.post('/api/v1/segnalazioni', urlencodedparser, (req, res) => {
  console.info("BEGIN post /api/v1/segnalazioni")
  const segnalazione = req.body;

  if (!hasRole(req,"ES")){
    res.status(401).end();
    return;
  }

  pool.query(
    "INSERT INTO segnalazioni (id_mezzo, id_tipo_segnalazione, data, km, note, ins_user) VALUES ($1, $2, $3, $4, $5, $6)",
    [segnalazione.idMezzo, segnalazione.idTipoSegnalazione, segnalazione.data, segnalazione.km, segnalazione.note, req.user.email],
    (error, results) => {
      if (error) {
        console.error(error)
        res.status(500).json({
          error: 'Errore imprevisto'
        });
      } else {
        getVehicleFaultReporting(segnalazione.idMezzo);
        res.status(201).end();
      }
      console.info("END post /api/v1/segnalazioni")
    }
  );
});

app.put('/api/v1/segnalazioni', urlencodedparser, (req, res) => {
  console.info("BEGIN put /api/v1/segnalazioni")
  const segnalazione = req.body;

  pool.query(
    "UPDATE segnalazioni set data = $1, km = $2, id_tipo_segnalazione = $3, note = $4, mod_data = now(), mod_user = $6 WHERE id_segnalazione = $5",
    [segnalazione.data, segnalazione.km, segnalazione.idTipoSegnalazione, segnalazione.note, segnalazione.idSegnalazione, req.user.email],
    (error, results) => {
      if (error) {
        console.error(error)
        res.status(500).json({
          error: 'Errore imprevisto'
        });
      } else {
        getVehicleFaultReporting(segnalazione.idMezzo);
        res.status(204).end();
      }
      console.info("END put /api/v1/segnalazioni")
    }
  );
});

app.get("/api/v1/tipisegnalazione", (req, res) => {
  console.info("BEGIN get /api/v1/tipisegnalazione")
  //const idMezzo = req.query.idMezzo;
  pool.query(
    "SELECT * FROM tipi_segnalazione", // WHERE id_mezzo = $1", [idMezzo],
    (error, results) => {
      if (error) {
        console.error(error)
        res.status(500).json({
          error: 'Errore imprevisto'
        });
      } else {
        if (results.rows && results.rows.length > 0) {
          res.status(200).json(results.rows);
        } else {
          res.status(404).json({
            error: 'Tipi di segnalazione non trovati'
          });
        }
      }
      console.info("END get /api/v1/tipisegnalazione")
    }
  );
});

app.get("/api/v1/segnalazioni/", (req, res) => {
  console.info("BEGIN get /api/v1/segnalazioni/")
  const idMezzo = req.query.idMezzo;
  if (idMezzo != null) {
    pool.query(
      "SELECT * FROM v_segnalazioni WHERE id_mezzo = $1 AND aperta = TRUE order by id_segnalazione desc limit 1", [idMezzo],
      (error, results) => {
        if (error) {
          console.error(error)
          res.status(500).json({
            error: 'Errore imprevisto'
          });
        } else {
          res.status(200).json(results.rows);
        }
        console.info("END get /api/v1/segnalazioni/")
      }
    );
  } else {
    pool.query(
      "SELECT * FROM v_segnalazioni order by descrizione_sede, codice_mezzo",
      (error, results) => {
        if (error) {
          console.error(error)
          res.status(500).json({
            error: 'Errore imprevisto'
          });
        } else {
          res.status(200).json(results.rows);
        }
        console.info("END get /api/v1/segnalazioni/")
      }
    );
  }
});

app.get("/api/v1/segnalazioni/datatable", (req, res) => {
  console.info("BEGIN get /api/v1/segnalazioni/datatable")
  //const q = req.query.q;
  pool.query(
    "SELECT id_segnalazione, codice_mezzo, descrizione_costruttore, codice_sede, descrizione_sede, descrizione_tipo_segnalazione, data, aperta FROM v_segnalazioni where eliminato = false order by data desc",
    (error, results) => {
      if (error) {
        console.error(error)
        res.status(500).json({
          error: 'Errore imprevisto'
        });
      } else {
        let segnalazioni = {}
        segnalazioni.data = results.rows
        if (req.user.sedi.length > 0){
          console.log(req.user.sedi);
          let sede = req.user.sedi[0];
          segnalazioni.data = segnalazioni.data.filter( s => s.codice_sede == sede)
        }
        res.status(200).json(segnalazioni);
      }
      console.info("END get /api/v1/segnalazioni/datatable")
    }
  );
});

app.get("/api/v1/segnalazioni/:id", (req, res) => {
  console.info("BEGIN get /api/v1/segnalazioni/:id")
  const id = req.params.id

  pool.query(
    "SELECT * FROM v_segnalazioni WHERE id_segnalazione = $1",
    [id],
    (error, results) => {
      if (error) {
        console.error(error)
        res.status(500).json({
          error: 'Errore imprevisto'
        });
      } else {
        if (results.rows && results.rows.length == 1) {
          res.status(200).json(results.rows[0]);
        } else {
          res.status(404).json({
            error: 'Segnalazione non trovata'
          });
        }
      }
      console.info("END get /api/v1/segnalazioni/:id")
    }
  );
});

app.delete("/api/v1/segnalazioni/:id", (req, res) => {
  console.info("BEGIN delete /api/v1/segnalazioni/:id")
  const id = req.params.id

  pool.query(
    "select * from segnalazioni WHERE id_segnalazione = $1 and eliminato = false",
    [id],
    (error, results) => {
      if (error) {
        console.error(error)
        res.status(500).json({
          error: 'Errore imprevisto'
        }).end();
      } else {
        if (results.rows && results.rows.length == 1) {
          segnalazione = results.rows[0];
          pool.query(
            "UPDATE segnalazioni set eliminato = true, mod_data = now(), mod_user = $2 WHERE id_segnalazione = $1",
            [id, req.user.email],
            (error, results) => {
              if (error) {
                console.error(error)
                res.status(500).json({
                  error: 'Errore imprevisto'
                }).end();
              }
              getVehicleFaultReporting(segnalazione.id_mezzo);
              res.status(204).end();
            }
          );
        } else {
          console.error('Errore imprevisto');
          res.status(500).json({
            error: 'Errore imprevisto'
          }).end();
        }
      }
      console.info("END delete /api/v1/segnalazioni/:id")
    }
  );
});

app.patch("/api/v1/segnalazioni/:id", (req, res) => {
  console.info("BEGIN patch /api/v1/segnalazioni/:id")
  const id = req.params.id

  pool.query(
    "update segnalazioni set aperta = FALSE WHERE id_segnalazione = $1",
    [id],
    (error, results) => {
      if (error) {
        console.error(error)
        res.status(500).json({
          error: 'Errore imprevisto'
        }).end();
      } else {
        getVehicleFaultReporting(segnalazione.idMezzo);
        res.status(204).end();
      }
      console.info("END patch /api/v1/segnalazioni/:id")
    }
  );
});
//SEGNALAZIONI END

async function getMezzoById(idMezzo){
  let mezzo = null;
  const results = await pool.query("select * from v_mezzi where id_mezzo = $1",[idMezzo]);
  if (results.rows && results.rows.length == 1){
    mezzo = results.rows[0];
  } 
  return mezzo;
}

async function getTipoComunicazioneById(idComunicazione){
  let tipoComunicazione = null;
  const results = await pool.query("select * from tipi_comunicazione where id_tipo_comunicazione = $1",[idComunicazione]);
  if (results.rows && results.rows.length == 1){
    tipoComunicazione = results.rows[0];
  } 
  return tipoComunicazione;
}

//COMUNICAZIONI BEGIN
app.post('/api/v1/comunicazioni', urlencodedparser, async (req, res) => {
  console.info("BEGIN post /api/v1/comunicazioni")
  const comunicazione = req.body;

  const mezzo = await getMezzoById(comunicazione.idMezzo);
  const mezzoFolderId = mezzo.id_fascicolo;
  console.debug("mezzoFolderId", mezzoFolderId);

  const tipoComunicazione = await getTipoComunicazioneById(comunicazione.idTipoComunicazione);
  const templateId = tipoComunicazione.id_template;
  const templateTitle = tipoComunicazione.titolo_template;
  const templateMapping= tipoComunicazione.mapping;
  console.debug("templateId", templateId);
  console.debug("templateTitle", templateTitle);
  console.debug("templateMapping", templateMapping);

  
  let docNumber = await getNextNumeroFromComunicazioniBySede(comunicazione.idMezzo);
  comunicazione.numero = docNumber;
  console.debug("numero",comunicazione.numero);
  
  if (comunicazione.idTipoManutenzione==0){
    comunicazione.descrizioneTipoManutenzione = "correttiva";
  } else {
    let descrizioneTipoManutenzione = await getTipoManutenzioneById(comunicazione.idTipoManutenzione);
    if (descrizioneTipoManutenzione != null){
      comunicazione.descrizioneTipoManutenzione = descrizioneTipoManutenzione.codice_tipo_manutenzione
    } else {
      comunicazione.descrizioneTipoManutenzione = "";
    }
  }
  console.debug("comunicazione.descrizioneTipoManutenzione",comunicazione.descrizioneTipoManutenzione);

  
  const mapping = ejs.render(templateMapping, {
    user: req.user, 
    mezzo: mezzo,
    comunicazione: comunicazione,
    moment: require('moment')
  });

  const owner = req.user.email;
  const documentId = await authorize(req, generateDocFromTemplate, owner, templateId, templateTitle, docNumber, mezzoFolderId, mapping);
  console.debug("documentId", documentId);
  if (documentId == null){
    res.status(500).json({
      error: 'Errore imprevisto: id documento null'
    });
    return
  }
  
  console.debug("comunicazione",comunicazione);

  pool.query(
    "INSERT INTO comunicazioni (numero, id_mezzo, id_tipo_comunicazione, id_tipo_manutenzione, num_ordine_lavoro, note, data, data_disponibilita, id_documento, ins_user) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    [comunicazione.numero, comunicazione.idMezzo, comunicazione.idTipoComunicazione, comunicazione.idTipoManutenzione, comunicazione.numeroOrdineLavoro, comunicazione.note, comunicazione.data, comunicazione.dataDisponibilita, documentId, req.user.email],
    (error, results) => {
      if (error) {
        console.error(error)
        res.status(500).json({
          error: 'Errore imprevisto'
        });
      } else {
        res.status(201).end();

        //se il tipo di comunicazione è tale per cui il mezzo deve cambiare stato, se la data di disponibilità è oggi cambio stato immediatamente,
        //altrimenti pianifico il cambio stato
        //TODO recuperare stato di arrivo dalla configurazione presente nella tabella dei tipi_comunicazione: id_tipo_comunicazione -> id_stato 
        
        if (["2", "3"].includes(comunicazione.idTipoComunicazione)) {

          if (comunicazione.dataDisponibilita == formatDate(new Date())){
            pool.query(
              "UPDATE rel_mezzi_stati set data_fine = NOW() where id_mezzo = $1",
              [comunicazione.idMezzo],
              (error, results) => {
                if (error) {
                  console.error(error)
                  res.status(500).json({
                    error: 'Errore imprevisto'
                  });
                } else {
                  pool.query(
                    "INSERT INTO rel_mezzi_stati (id_stato, id_mezzo, data_inizio, note) VALUES ($1, $2, now(), $3)",
                    [comunicazione.idStato, comunicazione.idMezzo, "Cambio stato in seguito a comunicazione con id: " + comunicazione.idTipoComunicazione],
                    (error, results) => {
                      if (error) {
                        console.error(error);
                        res.status(500).json({
                          error: 'Errore imprevisto'
                        });
                      } else {
                        res.status(201).end();
                      }
                    }
                  );
                }
                console.info("END post /api/v1/statimezzo")
              }
            );
          } else {
            pool.query(
              "INSERT INTO schedula_mezzi_stati (id_stato, id_mezzo, data) VALUES ($1, $2, $3)",
              [comunicazione.idStato, comunicazione.idMezzo, comunicazione.dataDisponibilita],
              (error, results) => {
                if (error) {
                  console.error(error);
                  res.status(500).json({
                    error: 'Errore imprevisto'
                  });
                } else {
                  res.status(201).end();
                }
              }
            );

          }
        } else {
          res.status(201).end();
        }
        


      }
      console.info("END post /api/v1/comunicazioni")
    }
  );
});

app.put('/api/v1/comunicazioni', urlencodedparser, (req, res) => {
  console.info("BEGIN put /api/v1/comunicazioni")
  const comunicazione = req.body;

  pool.query(
    "UPDATE comunicazioni set data = $1, data_disponibilita = $2,  id_tipo_manutenzione = $3, id_tipo_comunicazione = $4, num_ordine_lavoro = $5, note = $6,   mod_data = now(), mod_user = $8 WHERE id_comunicazione = $7",
    [comunicazione.data, comunicazione.dataDisponibilita, comunicazione.idTipoManutenzione,   comunicazione.idTipoComunicazione, comunicazione.numeroOrdineLavoro, comunicazione.note, comunicazione.idComunicazione, req.user.email],
    (error, results) => {
      if (error) {
        console.error(error)
        res.status(500).json({
          error: 'Errore imprevisto'
        });
      } else {
        res.status(204).end();
      }
      console.info("END put /api/v1/comunicazioni")
    }
  );

});

app.get("/api/v1/tipicomunicazione", (req, res) => {
  //const idMezzo = req.query.idMezzo;
  console.info("BEGIN get /api/v1/tipicomunicazione")
  pool.query(
    "SELECT * FROM tipi_comunicazione where codici_ruolo_mittenti like $1", [ '%' + req.user.ruoli[0] + '%'],// WHERE id_mezzo = $1", [idMezzo],
    (error, results) => {
      if (error) {
        console.error(error)
        res.status(500).json({
          error: 'Errore imprevisto'
        });
      } else {
        if (results.rows && results.rows.length > 0) {
          res.status(200).json(results.rows);
        } else {
          res.status(404).json({
            error: 'Tipi di comunicazione non trovati'
          });
        }
      }
      console.info("END get /api/v1/tipicomunicazione")
    }
  );
});

app.get("/api/v1/tipicomunicazione/all", (req, res) => {
  //const idMezzo = req.query.idMezzo;
  console.info("BEGIN get /api/v1/tipicomunicazione")
  pool.query(
    "SELECT * FROM tipi_comunicazione",
    (error, results) => {
      if (error) {
        console.error(error)
        res.status(500).json({
          error: 'Errore imprevisto'
        });
      } else {
        if (results.rows && results.rows.length > 0) {
          res.status(200).json(results.rows);
        } else {
          res.status(404).json({
            error: 'Tipi di comunicazione non trovati'
          });
        }
      }
      console.info("END get /api/v1/tipicomunicazione")
    }
  );
});

app.get("/api/v1/comunicazioni/", (req, res) => {
  console.info("BEGIN get /api/v1/comunicazioni/")
  //const q = req.query.q;
  pool.query(
    "SELECT * FROM v_comunicazioni order by descrizione_sede, codice_mezzo",
    (error, results) => {
      if (error) {
        console.error(error)
        res.status(500).json({
          error: 'Errore imprevisto'
        });
      } else {
        res.status(200).json(results.rows);
      }
      console.info("END get /api/v1/comunicazioni/")
    }
  );
});

app.get("/api/v1/comunicazioni/datatable", (req, res) => {
  console.info("BEGIN get /api/v1/comunicazioni/datatable")
  //const q = req.query.q;
  pool.query(
    "SELECT codice_mezzo, descrizione_costruttore, codice_sede, descrizione_sede, descrizione_tipo_comunicazione, data, id_documento, id_comunicazione, codici_ruolo_mittenti FROM v_comunicazioni where eliminato = false order by data desc",
    (error, results) => {
      if (error) {
        console.error(error)
        res.status(500).json({
          error: 'Errore imprevisto'
        });
      } else {
        let comunicazioni = {}
        comunicazioni.data = results.rows
        if (req.user.sedi.length > 0){
          console.log(req.user.sedi);
          let sede = req.user.sedi[0];
          comunicazioni.data = comunicazioni.data.filter( s => s.codice_sede == sede)
        }
        res.status(200).json(comunicazioni);
      }
      console.info("END get /api/v1/comunicazioni/datatable")
    }
  );
});

app.get("/api/v1/comunicazioni/:id", (req, res) => {
  console.info("BEGIN get /api/v1/comunicazioni/:id")
  const id = req.params.id

  pool.query(
    "SELECT * FROM v_comunicazioni WHERE id_comunicazione = $1",
    [id],
    (error, results) => {
      if (error) {
        console.error(error)
        res.status(500).json({
          error: 'Errore imprevisto'
        });
      } else {
        if (results.rows && results.rows.length == 1) {
          res.status(200).json(results.rows[0]);
        } else {
          res.status(404).json({
            error: 'Comunicazioni non trovata'
          });
        }
      }
      console.info("END get /api/v1/comunicazioni/:id")
    }
  );
});

app.delete("/api/v1/comunicazioni/:id", (req, res) => {
  console.info("BEGIN delete /api/v1/comunicazioni/:id")
  const id = req.params.id

  pool.query(
    "UPDATE comunicazioni set eliminato = true, mod_data = now(), mod_user = $2 WHERE id_comunicazione = $1",
    [id, req.user.email],
    (error, results) => {
      if (error) {
        console.error(error)
        res.status(500).json({
          error: 'Errore imprevisto'
        });
      } else {
        res.status(204).end();
      }
      console.info("END delete /api/v1/comunicazioni/:id")
    }
  );

});

async function getNextNumeroFromComunicazioniBySede(idMezzo){
  let numero = 1;
  let results = null;
  try {
    results = await pool.query(
      `select coalesce(
        (select max(numero) + 1 as numero
        from comunicazioni com
        join rel_mezzi_sedi mez on com.id_mezzo = mez.id_mezzo
        join sedi sed on mez.id_sede = sed.id_sede
        where com.id_mezzo = $1
        group by codice_sede),
        1) as numero
      `,
      [idMezzo]);
  } catch (error) {
    console.error(error);
  }
  if (results && results.rows.length > 0) {
    numero = results.rows[0].numero
  }

  return numero;
}

async function getTipoManutenzioneById(idTipoManutenzione){
  let tipo = null;
  let results = null;
  try {
    results = await pool.query(
      "select * from tipi_manutenzione where id_tipo_manutenzione = $1",[idTipoManutenzione]);
  } catch (error) {
    console.error(error);
  }
  if (results && results.rows.length > 0) {
    tipo = results.rows[0]
  }
  return tipo;
}
//COMUNICAZIONI END


//DEBUG
app.get("/api/v1/test", (req, res) => {
  //updateStatus();
  //calculateDeadlines();
  res.status(200).end();
});


//calcola le scadenze su tutta la flotta
const calculateDeadlines = function () {
  console.info("BEGIN calculateDeadlines")
  pool.query(
    "SELECT * FROM v_mezzi",
    (error, results) => {
      if (error) {
        console.error(error)
        res.status(500).json({
          error: 'Errore imprevisto'
        });
      } else {
        if (results.rows) {
          for (let i = 0; i < results.rows.length; i++) {
            console.debug("aggiornamento scadenze per mezzo con id:" + i)
            let mezzo = results.rows[i];
            calculateVehicleDeadline(mezzo.id_mezzo);
          }
        }
      }
      console.info("END calculateDeadlines")
    }
  );
};

//aggiorna lo stato dei mezzi sulla base dei cambi di stato programmati
function updateStatus(){
  console.info("BEGIN updateStatus")
  try {
    pool.query("SELECT * FROM schedula_mezzi_stati where data = CURRENT_DATE",
    (error, results) => {
      if (error) {
        console.error(error)
      } else {
        for(let i = 0; i < results.rows.length; i++){
          upd = results.rows[i];
          
          pool.query(
            "UPDATE rel_mezzi_stati set data_fine = NOW() where id_mezzo = $1",
            [upd.id_mezzo],
            (error, results) => {
              if (error) {
                console.error("updateStatus", error)
              } else {
                pool.query(
                  "INSERT INTO rel_mezzi_stati (id_stato, id_mezzo, data_inizio) VALUES ($1, $2, now())",
                  [upd.id_stato, upd.id_mezzo],
                  (error, results) => {
                    if (error) {
                      console.error("updateStatus", error);
                    } 
                  }
                );
              }
            }
          );
        }
      }
    });
  } catch (error) {
    console.error("updateStatus", error);
  }
  console.info("END updateStatus")
}


async function calculateVehicleDeadline(idMezzo) {
  console.info("BEGIN calculateVehicleDeadline")
  let codiceTipoAlert = "";
  let infoAlert = [];
  let results = null;
  //recupero l'elenco delle manutenzioni per il mezzo
  try {
    results = await pool.query(
      `select 
      tmtm.id_tipo_manutenzione,

      tmtm.cadenza_km, tmtm.tolleranza_positiva_km, tmtm.tolleranza_negativa_km, 
      tmtm.cadenza_ore, tmtm.tolleranza_positiva_ore, tmtm.tolleranza_negativa_ore, 
      tmtm.cadenza_ore_solari, tmtm.tolleranza_positiva_ore_solari, tmtm.tolleranza_negativa_ore_solari, 

      tma.codice_tipo_manutenzione
          from rel_tipi_mezzo_tipi_manutenzione tmtm
          left join tipi_mezzo tm on tmtm.id_tipo_mezzo = tm.id_tipo_mezzo
          left join mezzi m on tmtm.id_tipo_mezzo = m.id_tipo_mezzo
        left join tipi_manutenzione tma on tmtm.id_tipo_manutenzione = tma.id_tipo_manutenzione
      where m.id_mezzo = $1 order by tma.codice_tipo_manutenzione`,
      [idMezzo]);
  } catch (error) {
    console.error(error);
  }

  try {

    if (results && results.rows) {
      for (let i = 0; i < results.rows.length; i++) {
        let tipoManutenzione = results.rows[i];
        let alertMezzo = await getManteinanceVehicleDeadline(idMezzo, tipoManutenzione);
        if (alertMezzo.detail){
          infoAlert.push(alertMezzo.detail);
        }
        
        /*
        let segnalazioniMezzo = await getVehicleFaultReporting(idMezzo);
        if (segnalazioniMezzo) {
          infoAlert.push(segnalazioniMezzo.detail);
        }
        */
        if ( alertMezzo.detail && alertMezzo.detail.type == "ERROR") {
          codiceTipoAlert = "ERROR";
        } else if ((alertMezzo.detail && alertMezzo.detail.type == "WARNING") && codiceTipoAlert != "ERROR") {
          codiceTipoAlert = "WARNING";
        }
      }
    }

    if (results.rows.length == 0) {
      codiceTipoAlert = "ERROR";
      let detail = {
        message: "Non sono state ancora configurate manutenzioni per il mezzo",
        type: "ERROR"
      }
      infoAlert.push(detail)
    }

    //check km
    try {
      resultReg = await pool.query("SELECT * FROM registrazioni WHERE id_mezzo = $1 AND id_tipo_manutenzione = 0 AND corrente = true", [idMezzo]);
    } catch (error) {
      console.error(error);
      return null;
    }
    if (resultReg.rows == null || resultReg.rows.length == 0) {
      codiceTipoAlert = "ERROR";
      let detail = {
        message: "Non è stata trovata nessuna registrazione per i km e i km di vita del mezzo",
        type: "ERROR"
      }
      infoAlert.push(detail)
    }

  } catch (error) {
    console.error(error);
  }

  //aggiungere campo per prossima scadenza
  await pool.query(
    "UPDATE mezzi set codice_tipo_alert = $1 , dettagli_alert = $2 where id_mezzo = $3",
    [codiceTipoAlert, JSON.stringify(infoAlert), idMezzo]);

  console.info("END calculateVehicleDeadline")
  return codiceTipoAlert;
}

async function getManteinanceVehicleDeadline(idMezzo, tipoManutenzione) {
  console.info("BEGIN getManteinanceVehicleDeadline")
  let info = {};
  //recupero ultima registrazione km,km_vita per quel mezzo
  let resultReg = null;
  try {
    resultReg = await pool.query("SELECT * FROM registrazioni WHERE id_mezzo = $1 AND id_tipo_manutenzione = 0 AND corrente = true", [idMezzo]);
  } catch (error) {
    console.error(error);
    return null;
  }

  if (resultReg.rows && resultReg.rows.length == 1) {
    let registrazioneDati = resultReg.rows[0];
    console.debug("trovata ultima registrazione");
    //recupero ultima manutenzione di uno specifico tipo per quel mezzo
    const results = await pool.query(
      "SELECT * FROM manutenzioni WHERE id_mezzo = $1 AND id_tipo_manutenzione = $2 AND corrente = true",
      [idMezzo, tipoManutenzione.id_tipo_manutenzione]);
    if (results.rows && results.rows.length == 1) {
      let registrazioneManutenzione = results.rows[0];

      if (tipoManutenzione.cadenza_km > 0) { //cadenza chilometrica
        if ((registrazioneDati.km - registrazioneManutenzione.km) >= tipoManutenzione.tolleranza_positiva_km && (registrazioneDati.km - registrazioneManutenzione.km) < tipoManutenzione.cadenza_km){
          let scadenza = registrazioneManutenzione.km + tipoManutenzione.cadenza_km;
          console.debug("la manutenzione con codice '" + tipoManutenzione.codice_tipo_manutenzione + "' scadrà ai " + scadenza + " km");

          let message = "la manutenzione con codice '" + tipoManutenzione.codice_tipo_manutenzione + "' scadrà ai " + scadenza + " km";
          let detail = {
            codice: tipoManutenzione.codice_tipo_manutenzione,
            tolleranza_positiva_km: tipoManutenzione.tolleranza_positiva_km,
            tolleranza_negativa_km: tipoManutenzione.tolleranza_negativa_km,
            scadenza: scadenza,
            message: message,
            um : "km",
            type: "WARNING"
          }
          info.detail = detail;
          console.debug(message);
        }
        else if ((registrazioneDati.km - registrazioneManutenzione.km) < tipoManutenzione.cadenza_km) {
          let scadenza = registrazioneManutenzione.km + tipoManutenzione.cadenza_km;
          console.debug("la manutenzione con codice '" + tipoManutenzione.codice_tipo_manutenzione + "' scadrà ai " + scadenza + " km");

          let message = "la manutenzione con codice '" + tipoManutenzione.codice_tipo_manutenzione + "' scadrà ai " + scadenza + " km";
          let detail = {
            codice: tipoManutenzione.codice_tipo_manutenzione,
            tolleranza_positiva_km: tipoManutenzione.tolleranza_positiva_km,
            tolleranza_negativa_km: tipoManutenzione.tolleranza_negativa_km,
            scadenza: scadenza,
            message: message,
            um : "km",
            type: "INFO"
          }
          info.detail = detail;
          console.debug(message);

        } else if ((registrazioneDati.km - registrazioneManutenzione.km) < tipoManutenzione.tolleranza_negativa_km) {
          let kmScaduta = (registrazioneDati.km - registrazioneManutenzione.km - tipoManutenzione.cadenza_km);
          let kmTolleranza = (tipoManutenzione.tolleranza_negativa_km - (registrazioneDati.km - registrazioneManutenzione.km));
          let message = "la manutenzione con codice '" + tipoManutenzione.codice_tipo_manutenzione + "' è scaduta da " + kmScaduta + " km ma hai ancora " + kmTolleranza + " km di tolleranza"
          let detail = {
            codice: tipoManutenzione.codice_tipo_manutenzione,
            kmScaduta: kmScaduta,
            kmTolleranza: kmTolleranza,
            tolleranza_positiva_km: tipoManutenzione.tolleranza_positiva_km,
            tolleranza_negativa_km: tipoManutenzione.tolleranza_negativa_km,
            message: message,
            um : "km",
            type: "WARNING"
          }
          info.detail = detail;
          console.debug(message);
        } else if ((registrazioneDati.km - registrazioneManutenzione.km) >= tipoManutenzione.tolleranza_positiva_km) {
          let kmScaduta = (registrazioneDati.km - registrazioneManutenzione.km - tipoManutenzione.cadenza_km);
          let kmTolleranza = 0;
          let message = "la manutenzione con codice '" + tipoManutenzione.codice_tipo_manutenzione + "' è scaduta da " + kmScaduta + " km"; // e sono stati percorsi i " + (tipoManutenzione.tolleranza_negativa_km - tipoManutenzione.cadenza_km) + " km di tolleranza";
          let detail = {
            codice: tipoManutenzione.codice_tipo_manutenzione,
            kmScaduta: kmScaduta,
            kmTolleranza: kmTolleranza,
            tolleranza_positiva_km: tipoManutenzione.tolleranza_positiva_km,
            tolleranza_negativa_km: tipoManutenzione.tolleranza_negativa_km,
            message: message,
            um : "km",
            type: "ERROR"
          }
          info.detail = detail;
          console.debug(message);
        } else {
          let message = "Errore inaspettato nel calcolo della scadenza";
          let detail = {
            message: message,
            type: "ERROR"
          }
          info.detail = detail;
          console.debug(message);
        }
      } 

      if ( (info.detail == null || !["WARNING","ERROR"].includes(info.detail.type)) && tipoManutenzione.tolleranza_positiva_ore_solari > 0) { //cadenza oraria solare
        if ( ore_trascorse(false, registrazioneManutenzione.data) >= tipoManutenzione.tolleranza_positiva_ore_solari && ore_trascorse(false, registrazioneManutenzione.data) < tipoManutenzione.cadenza_ore_solari) {
          let scadenza = tipoManutenzione.cadenza_ore_solari - ore_trascorse(false, registrazioneManutenzione.data) ;
          console.debug("la manutenzione con codice '" + tipoManutenzione.codice_tipo_manutenzione + "' scadrà tra " + scadenza + " ore solari");

          let message = "la manutenzione con codice '" + tipoManutenzione.codice_tipo_manutenzione + "' scadrà tra " + scadenza + " ore solari";
          let detail = {
            codice: tipoManutenzione.codice_tipo_manutenzione,
            tolleranza_positiva_ore: tipoManutenzione.tolleranza_positiva_ore_solari,
            tolleranza_negativa_ore: tipoManutenzione.tolleranza_negativa_ore_solari,
            scadenza: scadenza,
            message: message,
            um : "ore_solari",
            type: "WARNING"
          }
          info.detail = detail;
          console.debug(message);

        } else if ( ore_trascorse(false, registrazioneManutenzione.data) < tipoManutenzione.cadenza_ore_solari) {
          let scadenza = tipoManutenzione.cadenza_ore_solari - ore_trascorse(false, registrazioneManutenzione.data) ;
          console.debug("la manutenzione con codice '" + tipoManutenzione.codice_tipo_manutenzione + "' scadrà tra " + scadenza + " ore solari");

          let message = "la manutenzione con codice '" + tipoManutenzione.codice_tipo_manutenzione + "' scadrà tra " + scadenza + " ore solari";
          let detail = {
            codice: tipoManutenzione.codice_tipo_manutenzione,
            tolleranza_positiva_ore: tipoManutenzione.tolleranza_positiva_ore_solari,
            tolleranza_negativa_ore: tipoManutenzione.tolleranza_negativa_ore_solari,
            scadenza: scadenza,
            message: message,
            um : "ore_solari",
            type: "INFO"
          }
          info.detail = detail;
          console.debug(message);

        } else if ( (ore_trascorse(false, registrazioneManutenzione.data)) < tipoManutenzione.tolleranza_negativa_ore_solari) {
          let oreScaduta = ore_trascorse(false, registrazioneManutenzione.data) - tipoManutenzione.cadenza_ore_solari;
          let oreTolleranza = (tipoManutenzione.tolleranza_negativa_ore_solari - (ore_trascorse(false, registrazioneManutenzione.data) ));
          let message = "la manutenzione con codice '" + tipoManutenzione.codice_tipo_manutenzione + "' è scaduta da " + oreScaduta + " ore solari ma hai ancora " + oreTolleranza + " ore solari di tolleranza"
          let detail = {
            codice: tipoManutenzione.codice_tipo_manutenzione,
            oreScaduta: oreScaduta,
            oreTolleranza: oreTolleranza,
            tolleranza_positiva_ore: tipoManutenzione.tolleranza_positiva_ore_solari,
            tolleranza_negativa_ore: tipoManutenzione.tolleranza_negativa_ore_solari,
            message: message,
            um : "ore_solari",
            type: "WARNING"
          }
          info.detail = detail;
          console.debug(message);
        } else if ( (ore_trascorse(false, registrazioneManutenzione.data) ) >= tipoManutenzione.tolleranza_negativa_ore_solari) {
          let oreScaduta = ore_trascorse(false, registrazioneManutenzione.data) - tipoManutenzione.cadenza_ore_solari;
          let oreTolleranza = 0;
          let message = "la manutenzione con codice '" + tipoManutenzione.codice_tipo_manutenzione + "' è scaduta da " + oreScaduta + " ore solari";// e sono trascorse le " + (tipoManutenzione.tolleranza_negativa_ore - tipoManutenzione.cadenza_ore) + " ore di tolleranza";
          let detail = {
            codice: tipoManutenzione.codice_tipo_manutenzione,
            oreScaduta: oreScaduta,
            oreTolleranza: oreTolleranza,
            tolleranza_positiva_ore: tipoManutenzione.tolleranza_positiva_ore_solari,
            tolleranza_negativa_ore: tipoManutenzione.tolleranza_negativa_ore_solari,
            message: message,
            um : "ore_solari",
            type: "ERROR"
          }
          info.detail = detail;
          console.debug(message);
        } else {
          let message = "Errore inaspettato nel calcolo della scadenza";
          let detail = {
            message: message,
            type: "ERROR"
          }
          info.detail = detail;
          console.debug(message);
        }
      }

      if ( (info.detail == null || !["WARNING","ERROR"].includes(info.detail.type)) && tipoManutenzione.cadenza_ore > 0) { //cadenza oraria
        if ( ore_trascorse(true, registrazioneManutenzione.data) >= tipoManutenzione.tolleranza_positiva_ore && ore_trascorse(true, registrazioneManutenzione.data) < tipoManutenzione.cadenza_ore) {
          let scadenza = tipoManutenzione.cadenza_ore - ore_trascorse(true, registrazioneManutenzione.data);
          console.debug("la manutenzione con codice '" + tipoManutenzione.codice_tipo_manutenzione + "' scadrà tra " + scadenza + " ore");

          let message = "la manutenzione con codice '" + tipoManutenzione.codice_tipo_manutenzione + "' scadrà tra " + scadenza + " ore";
          let detail = {
            codice: tipoManutenzione.codice_tipo_manutenzione,
            tolleranza_positiva_ore: tipoManutenzione.tolleranza_positiva_ore,
            tolleranza_negativa_ore: tipoManutenzione.tolleranza_negativa_ore,
            scadenza: scadenza,
            message: message,
            um : "ore",
            type: "WARNING"
          }
          info.detail = detail;
          console.debug(message);

        } else if ( ore_trascorse(true, registrazioneManutenzione.data) < tipoManutenzione.cadenza_ore) {
          let scadenza = tipoManutenzione.cadenza_ore - ore_trascorse(true, registrazioneManutenzione.data);
          console.debug("la manutenzione con codice '" + tipoManutenzione.codice_tipo_manutenzione + "' scadrà tra " + scadenza + " ore");

          let message = "la manutenzione con codice '" + tipoManutenzione.codice_tipo_manutenzione + "' scadrà tra " + scadenza + " ore";
          let detail = {
            codice: tipoManutenzione.codice_tipo_manutenzione,
            tolleranza_positiva_ore: tipoManutenzione.tolleranza_positiva_ore,
            tolleranza_negativa_ore: tipoManutenzione.tolleranza_negativa_ore,
            scadenza: scadenza,
            message: message,
            um : "ore",
            type: "INFO"
          }
          info.detail = detail;
          console.debug(message);

        } else if ( (ore_trascorse(true, registrazioneManutenzione.data)) < tipoManutenzione.tolleranza_negativa_ore) {
          let oreScaduta = ore_trascorse(true, registrazioneManutenzione.data) - tipoManutenzione.cadenza_ore;
          let oreTolleranza = (tipoManutenzione.tolleranza_negativa_ore - (ore_trascorse(true, registrazioneManutenzione.data) ));
          let message = "la manutenzione con codice '" + tipoManutenzione.codice_tipo_manutenzione + "' è scaduta da " + oreScaduta + " ore ma hai ancora " + oreTolleranza + " ore di tolleranza"
          let detail = {
            codice: tipoManutenzione.codice_tipo_manutenzione,
            oreScaduta: oreScaduta,
            oreTolleranza: oreTolleranza,
            tolleranza_positiva_ore: tipoManutenzione.tolleranza_positiva_ore,
            tolleranza_negativa_ore: tipoManutenzione.tolleranza_negativa_ore,
            message: message,
            um : "ore",
            type: "WARNING"
          }
          info.detail = detail;
          console.debug(message);
        } else if ( (ore_trascorse(true, registrazioneManutenzione.data) ) >= tipoManutenzione.tolleranza_negativa_ore) {
          let oreScaduta = ore_trascorse(true, registrazioneManutenzione.data) - tipoManutenzione.cadenza_ore;
          let oreTolleranza = 0;
          let message = "la manutenzione con codice '" + tipoManutenzione.codice_tipo_manutenzione + "' è scaduta da " + oreScaduta + " ore";// e sono trascorse le " + (tipoManutenzione.tolleranza_negativa_ore - tipoManutenzione.cadenza_ore) + " ore di tolleranza";
          let detail = {
            codice: tipoManutenzione.codice_tipo_manutenzione,
            oreScaduta: oreScaduta,
            oreTolleranza: oreTolleranza,
            tolleranza_positiva_ore: tipoManutenzione.tolleranza_positiva_ore,
            tolleranza_negativa_ore: tipoManutenzione.tolleranza_negativa_ore,
            message: message,
            um : "ore",
            type: "ERROR"
          }
          info.detail = detail;
          console.debug(message);
        } else {
          let message = "Errore inaspettato nel calcolo della scadenza";
          let detail = {
            message: message,
            type: "ERROR"
          }
          info.detail = detail;
          console.debug(message);
        }
      }



    } else {
      let message = "non è stata trovata nessuna registrazione per il tipo di manutenzione con codice '" + tipoManutenzione.codice_tipo_manutenzione + "'";
      let detail = {
        //codice: tipoManutenzione.codice_tipo_manutenzione,
        message: message,
        type: "ERROR"
      }
      info.detail = detail;
      console.debug(message);
    }
  } else {
    /*
    let message = "non è stata trovata nessuna registrazione per i km e i km di vita del mezzo";
    let detail = {
      message: message,
      type: "ERROR"
    }
    info.detail = detail;
    console.debug(message);
    */
  }
  console.info("END getManteinanceVehicleDeadline")
  return info;
}

async function getVehicleFaultReporting(idMezzo) {
  //recupero ultime segnalazioni aperte per quel mezzo
  console.info("BEGIN getVehicleFaultReporting")
  let result = null;
  try {
    result = await pool.query("SELECT * FROM v_segnalazioni WHERE id_mezzo = $1 AND aperta = true and eliminato = false", [idMezzo]);
  } catch (error) {
    console.error(error);
    console.info("END getVehicleFaultReporting")
    return null;
  }
  let info = [];
  if (result.rows && result.rows.length > 0) {
    for (let i = 0; i < result.rows.length; i++) {
      let segnalazione = result.rows[i];

      let message = "segnalato guasto con codice '" + segnalazione.codice_tipo_segnalazione + "'";
      let detail = {
        codice: segnalazione.codice_tipo_segnalazione,
        message: message
      }
      info.push(detail);
      console.debug(message);
    }

    await pool.query(
      "UPDATE mezzi set dettagli_segnalazione = $1 where id_mezzo = $2",
      [JSON.stringify(info), idMezzo]);

    console.info("END getVehicleFaultReporting")
    return info;
  } else {

    await pool.query(
      "UPDATE mezzi set dettagli_segnalazione = '' where id_mezzo = $1",
      [idMezzo]);

  }
  console.info("END getVehicleFaultReporting")


  //xxx
}

const formatDate = function(date){
  const day = new Date(date);
  const yyyy = day.getFullYear();
  let mm = day.getMonth() + 1; 
  let dd = day.getDate();

  if (dd < 10) dd = '0' + dd;
  if (mm < 10) mm = '0' + mm;

  return dd + '/' + mm + '/' + yyyy;
}

const formatDateTime = function(date){
  const day = new Date(date);
  const yyyy = day.getFullYear();
  let mm = day.getMonth() + 1; 
  let dd = day.getDate();
  let hh = day.getHours();
  let mn = day.getMinutes();

  if (dd < 10) dd = '0' + dd;
  if (mm < 10) mm = '0' + mm;

  if (hh < 10) hh = '0' + hh;
  if (mn < 10) mn = '0' + mn;

  return dd + '/' + mm + '/' + yyyy + " " + hh + ":" + mn;
}

const formatDateFolder = function(date){
  const day = new Date(date);
  const yyyy = day.getFullYear();
  let mm = day.getMonth() + 1; 
  let dd = day.getDate();

  if (dd < 10) dd = '0' + dd;
  if (mm < 10) mm = '0' + mm;

  return yyyy + mm + dd;
}

function time(date) {
  return new Date(
    date.getFullYear(),
    date.getMonth(),
    date.getDate()
  ).getTime();
}

const ore_trascorse = function(effective, date){
  var diff =( time(new Date()) - date.getTime()) / 1000;
  diff /= (60 * 60);
  hour = Math.round(diff);
  if (effective){
    hour = Math.round(hour / 3);
  }
  return hour;
}

const hasRole = function(req, ruoli){
  if (req.user && req.user.ruoli){
    userRoles = req.user.ruoli;
    let roles = getRolesFromString(ruoli);
    for(let i = 0; i < roles.length; i++){
      let role = roles[i];
      if (userRoles.includes(role)){
        return true;
      }
    }
    return userRoles.includes('ADMIN') || userRoles.includes('FSM');
  } else {
    return false;
  }
}

const getRolesFromString = function(rolesString){
    roles = [];
    rolesString = rolesString.replaceAll("[","");
    rolesString = rolesString.replaceAll("]","");
    rolesString = rolesString.replaceAll("']'","");
    if (rolesString.indexOf(',') > -1){
      roles = rolesString.split(',');
    } else {
      roles.push(rolesString);
    }
    return roles;
}

const convertAssociativeArrayToArray = function(data){
  let retArray = [];
  
  let header = [];
  let first = data[0];
  for (var key in first) {
    if (first.hasOwnProperty(key)) {
      header.push(key);
    }
  }
  retArray.push(header);

  for(let i = 1; i < data.length; i++){
    let row = [];
    let current = data[i];
    for (var key in current) {
      row.push(current[key]);
    }
    retArray.push(row);
  }
  return retArray;
}


//ricalcolo scadenze alle 23
cron.schedule('0 23 * * *', function () {
  console.info("BEGIN schedule calculateDeadlines")
  calculateDeadlines();
  console.info("END schedule calculateDeadlines")
});

//aggiornamento stati alle 01
cron.schedule('0 1 * * *', function () {
  console.info("BEGIN schedule updateStatus")
  updateStatus();
  console.info("END schedule updateStatus")
});
