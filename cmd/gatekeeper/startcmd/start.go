/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/orb"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	vdrpkg "github.com/hyperledger/aries-framework-go/pkg/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/httpbinding"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/rs/cors"
	"github.com/spf13/cobra"
	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"
	tlsutils "github.com/trustbloc/edge-core/pkg/utils/tls"

	"github.com/trustbloc/ace/cmd/common"
	"github.com/trustbloc/ace/pkg/client/csh/client"
	vaultclient "github.com/trustbloc/ace/pkg/client/vault"
	"github.com/trustbloc/ace/pkg/gatekeeper/config"
	"github.com/trustbloc/ace/pkg/restapi/gatekeeper"
	"github.com/trustbloc/ace/pkg/restapi/handler"
	"github.com/trustbloc/ace/pkg/restapi/healthcheck"
	"github.com/trustbloc/ace/pkg/restapi/mw/httpsigmw"
	"github.com/trustbloc/ace/pkg/restapi/mw/tokenauth"
	"github.com/trustbloc/ace/pkg/vcissuer"
)

const (
	hostURLFlagName      = "host-url"
	hostURLFlagShorthand = "u"
	hostURLFlagUsage     = "Host URL to run the gatekeeper instance on. Format: HostName:Port."
	hostURLEnvKey        = "GK_HOST_URL"

	tlsSystemCertPoolFlagName  = "tls-systemcertpool"
	tlsSystemCertPoolFlagUsage = "Use system certificate pool." +
		" Possible values [true] [false]. Defaults to false if not set." +
		" Alternatively, this can be set with the following environment variable: " + tlsSystemCertPoolEnvKey
	tlsSystemCertPoolEnvKey = "GK_TLS_SYSTEMCERTPOOL"

	tlsCACertsFlagName  = "tls-cacerts"
	tlsCACertsFlagUsage = "Comma-Separated list of ca certs path." +
		" Alternatively, this can be set with the following environment variable: " + tlsCACertsEnvKey
	tlsCACertsEnvKey = "GK_TLS_CACERTS"

	tlsServeCertPathFlagName  = "tls-serve-cert"
	tlsServeCertPathFlagUsage = "Path to the server certificate to use when serving HTTPS." +
		" Alternatively, this can be set with the following environment variable: " + tlsServeCertPathEnvKey
	tlsServeCertPathEnvKey = "GK_TLS_SERVE_CERT"

	tlsServeKeyPathFlagName  = "tls-serve-key"
	tlsServeKeyPathFlagUsage = "Path to the private key to use when serving HTTPS." +
		" Alternatively, this can be set with the following environment variable: " + tlsServeKeyPathFlagEnvKey
	tlsServeKeyPathFlagEnvKey = "GK_TLS_SERVE_KEY"

	// did resolver url.
	didResolverURLFlagName  = "did-resolver-url"
	didResolverURLFlagUsage = "DID Resolver URL."
	didResolverURLEnvKey    = "GK_DID_RESOLVER_URL"

	blocDomainFlagName  = "bloc-domain"
	blocDomainFlagUsage = "Bloc domain"
	blocDomainEnvKey    = "GK_BLOC_DOMAIN"

	// remote JSON-LD context provider url.
	contextProviderFlagName  = "context-provider-url"
	contextProviderEnvKey    = "GK_CONTEXT_PROVIDER_URL"
	contextProviderFlagUsage = "Remote context provider URL to get JSON-LD contexts from." +
		" This flag can be repeated, allowing setting up multiple context providers." +
		" Alternatively, this can be set with the following environment variable (in CSV format): " +
		contextProviderEnvKey

	// vault server url.
	vaultServerURLFlagName  = "vault-server-url"
	vaultServerURLFlagUsage = "URL of the vault server. This field is mandatory."
	vaultServerURLEnvKey    = "GK_VAULT_SERVER_URL"

	// did anchor origin.
	didAnchorOriginFlagName  = "did-anchor-origin"
	didAnchorOriginEnvKey    = "GK_DID_ANCHOR_ORIGIN"
	didAnchorOriginFlagUsage = "DID anchor origin. This field is mandatory." +
		" Alternatively, this can be set with the following environment variable: " +
		didAnchorOriginEnvKey

	// csh url.
	cshURLFlagName  = "csh-url"
	cshURLFlagUsage = "URL of the csh. This field is mandatory."
	cshURLEnvKey    = "GK_CSH_URL"

	// vc issuer server url.
	vcIssuerURLFlagName  = "vc-issuer-url"
	vcIssuerURLFlagUsage = "URL of the VC VCIssuer service. This field is mandatory."
	vcIssuerURLEnvKey    = "GK_VC_ISSUER_URL"

	// vc issuer profile.
	vcIssuerProfileFlagName  = "vc-issuer-profile"
	vcIssuerProfileFlagUsage = "Profile of the VC VCIssuer service. This field is mandatory."
	vcIssuerProfileEnvKey    = "GK_VC_ISSUER_PROFILE"

	requestTokensFlagName  = "request-tokens"
	requestTokensEnvKey    = "GK_REQUEST_TOKENS"
	requestTokensFlagUsage = "Tokens used for HTTP requests to other services" +
		" Alternatively, this can be set with the following environment variable: " + requestTokensEnvKey

	authTokenFlagName  = "api-token"
	authTokenEnvKey    = "GK_REST_API_TOKEN" //nolint: gosec
	authTokenFlagUsage = "Bearer token used for a token protected api calls. " +
		" Alternatively, this can be set with the following environment variable: " + authTokenEnvKey

	tokenLength2              = 2
	vcsIssuerRequestTokenName = "vcs_issuer"
	sidetreeRequestTokenName  = "sidetreeToken"
	keystorePrimaryKeyURI     = "local-lock://localkms"
)

var logger = log.New("gatekeeper-rest")

type tlsParameters struct {
	systemCertPool bool
	caCerts        []string
	serveCertPath  string
	serveKeyPath   string
}

type serviceParameters struct {
	host                string
	tlsParams           *tlsParameters
	dbParams            *common.DBParameters
	blocDomain          string
	didResolverURL      string
	contextProviderURLs []string
	vcIssuerURL         string
	vcIssuerProfile     string
	vaultServerURL      string
	didAnchorOrigin     string
	cshURL              string
	authToken           string
	requestTokens       map[string]string
}

type server interface {
	ListenAndServe(host string, certFile, keyFile string, router http.Handler) error
}

// HTTPServer represents an actual HTTP server implementation.
type HTTPServer struct{}

// ListenAndServe starts the server using the standard Go HTTP server implementation.
func (s *HTTPServer) ListenAndServe(host, certFile, keyFile string, router http.Handler) error {
	if certFile == "" || keyFile == "" {
		return http.ListenAndServe(host, router)
	}

	return http.ListenAndServeTLS(host, certFile, keyFile, router)
}

// GetStartCmd returns the Cobra start command.
func GetStartCmd(srv server) *cobra.Command {
	cmd := createStartCmd(srv)

	createFlags(cmd)

	return cmd
}

func getTLS(cmd *cobra.Command) (*tlsParameters, error) {
	tlsSystemCertPoolString := cmdutils.GetUserSetOptionalVarFromString(cmd, tlsSystemCertPoolFlagName,
		tlsSystemCertPoolEnvKey)

	tlsSystemCertPool := false

	if tlsSystemCertPoolString != "" {
		var err error

		tlsSystemCertPool, err = strconv.ParseBool(tlsSystemCertPoolString)
		if err != nil {
			return nil, err
		}
	}

	tlsCACerts := cmdutils.GetUserSetOptionalVarFromArrayString(cmd, tlsCACertsFlagName, tlsCACertsEnvKey)

	tlsServeCertPath := cmdutils.GetUserSetOptionalVarFromString(cmd, tlsServeCertPathFlagName, tlsServeCertPathEnvKey)

	tlsServeKeyPath := cmdutils.GetUserSetOptionalVarFromString(cmd, tlsServeKeyPathFlagName, tlsServeKeyPathFlagEnvKey)

	return &tlsParameters{
		systemCertPool: tlsSystemCertPool,
		caCerts:        tlsCACerts,
		serveCertPath:  tlsServeCertPath,
		serveKeyPath:   tlsServeKeyPath,
	}, nil
}

func createStartCmd(srv server) *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: "Starts Gatekeeper server",
		RunE: func(cmd *cobra.Command, args []string) error {
			params, err := getParameters(cmd)
			if err != nil {
				return err
			}

			return startService(params, srv)
		},
	}
}

func getParameters(cmd *cobra.Command) (*serviceParameters, error) { //nolint: funlen
	host, err := cmdutils.GetUserSetVarFromString(cmd, hostURLFlagName, hostURLEnvKey, false)
	if err != nil {
		return nil, err
	}

	tlsParams, err := getTLS(cmd)
	if err != nil {
		return nil, err
	}

	dbParams, err := common.DBParams(cmd)
	if err != nil {
		return nil, err
	}

	blocDomain, err := cmdutils.GetUserSetVarFromString(cmd, blocDomainFlagName, blocDomainEnvKey, true)
	if err != nil {
		return nil, err
	}

	didResolverURL, err := cmdutils.GetUserSetVarFromString(cmd,
		didResolverURLFlagName, didResolverURLEnvKey, true)
	if err != nil {
		return nil, err
	}

	contextProviderURLs, err := cmdutils.GetUserSetVarFromArrayString(cmd, contextProviderFlagName,
		contextProviderEnvKey, true)
	if err != nil {
		return nil, err
	}

	vaultServerURL, err := cmdutils.GetUserSetVarFromString(cmd, vaultServerURLFlagName,
		vaultServerURLEnvKey, false)
	if err != nil {
		return nil, err
	}

	didAnchorOrigin, err := cmdutils.GetUserSetVarFromString(cmd, didAnchorOriginFlagName,
		didAnchorOriginEnvKey, false)
	if err != nil {
		return nil, err
	}

	cshURL, err := cmdutils.GetUserSetVarFromString(cmd, cshURLFlagName,
		cshURLEnvKey, false)
	if err != nil {
		return nil, err
	}

	vcIssuerURL, err := cmdutils.GetUserSetVarFromString(cmd, vcIssuerURLFlagName, vcIssuerURLEnvKey, false)
	if err != nil {
		return nil, err
	}

	vcIssuerProfile, err := cmdutils.GetUserSetVarFromString(cmd, vcIssuerProfileFlagName, vcIssuerProfileEnvKey, false)
	if err != nil {
		return nil, err
	}

	requestTokens, err := getRequestTokens(cmd)
	if err != nil {
		return nil, err
	}

	authToken, err := cmdutils.GetUserSetVarFromString(cmd, authTokenFlagName,
		authTokenEnvKey, true)

	return &serviceParameters{
		host:                host,
		tlsParams:           tlsParams,
		dbParams:            dbParams,
		blocDomain:          blocDomain,
		didResolverURL:      didResolverURL,
		contextProviderURLs: contextProviderURLs,
		vcIssuerURL:         vcIssuerURL,
		vcIssuerProfile:     vcIssuerProfile,
		vaultServerURL:      vaultServerURL,
		didAnchorOrigin:     didAnchorOrigin,
		cshURL:              cshURL,
		authToken:           authToken,
		requestTokens:       requestTokens,
	}, err
}

func createFlags(cmd *cobra.Command) {
	cmd.Flags().StringP(hostURLFlagName, hostURLFlagShorthand, "", hostURLFlagUsage)
	cmd.Flags().StringP(tlsSystemCertPoolFlagName, "", "", tlsSystemCertPoolFlagUsage)
	cmd.Flags().StringArrayP(tlsCACertsFlagName, "", []string{}, tlsCACertsFlagUsage)
	cmd.Flags().StringP(tlsServeCertPathFlagName, "", "", tlsServeCertPathFlagUsage)
	cmd.Flags().StringP(tlsServeKeyPathFlagName, "", "", tlsServeKeyPathFlagUsage)
	cmd.Flags().StringP(blocDomainFlagName, "", "", blocDomainFlagUsage)
	cmd.Flags().StringP(didResolverURLFlagName, "", "", didResolverURLFlagUsage)
	cmd.Flags().StringArrayP(contextProviderFlagName, "", []string{}, contextProviderFlagUsage)
	cmd.Flags().StringP(vaultServerURLFlagName, "", "", vaultServerURLFlagUsage)
	cmd.Flags().StringP(didAnchorOriginFlagName, "", "", didAnchorOriginFlagUsage)
	cmd.Flags().StringP(cshURLFlagName, "", "", cshURLFlagUsage)
	cmd.Flags().StringP(vcIssuerURLFlagName, "", "", vcIssuerURLFlagUsage)
	cmd.Flags().StringP(vcIssuerProfileFlagName, "", "", vcIssuerProfileFlagUsage)
	cmd.Flags().StringArrayP(requestTokensFlagName, "", []string{}, requestTokensFlagUsage)
	cmd.Flags().StringP(authTokenFlagName, "", "", authTokenFlagUsage)

	common.Flags(cmd)
}

func startService(params *serviceParameters, srv server) error { // nolint: funlen,gocyclo
	rootCAs, err := tlsutils.GetCertPool(params.tlsParams.systemCertPool, params.tlsParams.caCerts)
	if err != nil {
		return err
	}

	tlsConfig := &tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS12}

	storeProvider, err := common.InitStore(params.dbParams, logger)
	if err != nil {
		return err
	}

	router := mux.NewRouter()

	// add health check endpoint
	healthCheckService := healthcheck.New()

	healthCheckHandlers := healthCheckService.GetOperations()
	for _, handler := range healthCheckHandlers {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	httpClient := &http.Client{Transport: &http.Transport{
		TLSClientConfig: tlsConfig,
	}}

	vdr, err := createVDR(params.didResolverURL, params.blocDomain, params.requestTokens[sidetreeRequestTokenName],
		httpClient)
	if err != nil {
		return err
	}

	ldStore, err := common.CreateLDStoreProvider(storeProvider)
	if err != nil {
		return err
	}

	documentLoader, err := common.CreateJSONLDDocumentLoader(ldStore, httpClient, params.contextProviderURLs)
	if err != nil {
		return err
	}

	vClient := vaultclient.New(params.vaultServerURL, vaultclient.WithHTTPClient(httpClient))

	cshClient := createCSHClient(params.cshURL, httpClient).Operations

	vcIssuer := vcissuer.New(&vcissuer.Config{
		VCIssuerURL:    params.vcIssuerURL,
		AuthToken:      params.requestTokens[vcsIssuerRequestTokenName],
		ProfileName:    params.vcIssuerProfile,
		DocumentLoader: documentLoader,
		HTTPClient:     httpClient,
	})

	keyManager, err := localkms.New(keystorePrimaryKeyURI, &kmsProvider{
		storageProvider: storeProvider,
		secretLock:      &noop.NoLock{},
	})
	if err != nil {
		return err
	}

	configService, err := config.NewService(&config.ServiceParams{
		StoreProvider:   storeProvider,
		CSHClient:       cshClient,
		VDR:             vdr,
		KeyManager:      keyManager,
		DidMethod:       orb.DIDMethod,
		DidAnchorOrigin: params.didAnchorOrigin,
	})
	if err != nil {
		return err
	}

	service, err := gatekeeper.New(&gatekeeper.Config{
		StorageProvider:        storeProvider,
		VaultClient:            vClient,
		ConfigService:          configService,
		VDR:                    vdr,
		VCIssuer:               vcIssuer,
		ConfidentialStorageHub: cshClient,
	})
	if err != nil {
		return err
	}

	httpSigMW := httpsigmw.New(&httpsigmw.Config{
		VDR: vdr,
	})

	tokenAuthMW := tokenauth.New(params.authToken)

	for _, operation := range service.GetOperations() {
		var h http.Handler
		h = operation.Handle()

		if operation.Auth() == handler.AuthHTTPSig {
			h = httpSigMW.Middleware(h)
		}

		if operation.Auth() == handler.AuthToken && params.authToken != "" {
			h = tokenAuthMW.Middleware(h)
		}

		router.Handle(operation.Path(), h).Methods(operation.Method())
	}

	hasConfig, err := configService.HasConfig()
	if err != nil {
		return err
	}

	if !hasConfig {
		err = configService.CreateConfig()
		if err != nil {
			return err
		}

		var conf *config.Config

		conf, err = configService.Get()
		if err != nil {
			return err
		}

		err = vcIssuer.CreateIssuerProfile(
			context.Background(),
			conf.DID,
			conf.PubKeyID,
			conf.PrivateKey,
		)

		if err != nil {
			return err
		}
	}

	// start server on given port and serve using given handlers
	return srv.ListenAndServe(params.host, params.tlsParams.serveCertPath, params.tlsParams.serveKeyPath,
		cors.New(cors.Options{
			AllowedMethods: []string{
				http.MethodHead,
				http.MethodGet,
				http.MethodPost,
				http.MethodDelete,
			},
			AllowedHeaders: []string{
				"Origin",
				"Accept",
				"Content-Type",
				"X-Requested-With",
				"Authorization",
			},
		}).Handler(router))
}

func createCSHClient(cshURL string, httpClient *http.Client) *client.ConfidentialStorageHub {
	cshURLParts := strings.Split(cshURL, "://")

	transport := httptransport.NewWithClient(
		cshURLParts[1],
		client.DefaultBasePath,
		[]string{cshURLParts[0]},
		httpClient,
	)

	return client.New(transport, strfmt.Default)
}

func getRequestTokens(cmd *cobra.Command) (map[string]string, error) {
	requestTokens, err := cmdutils.GetUserSetVarFromArrayString(cmd, requestTokensFlagName,
		requestTokensEnvKey, true)
	if err != nil {
		return nil, err
	}

	tokens := make(map[string]string)

	for _, token := range requestTokens {
		split := strings.Split(token, "=")
		switch len(split) {
		case tokenLength2:
			tokens[split[0]] = split[1]
		default:
			logger.Warnf("invalid token '%s'", token)
		}
	}

	return tokens, nil
}

func createVDR(didResolverURL, blocDomain, sidetreeToken string, httpClient *http.Client) (vdrapi.Registry, error) {
	var opts []vdrpkg.Option

	if didResolverURL != "" {
		didResolverVDRI, err := httpbinding.New(didResolverURL, httpbinding.WithHTTPClient(httpClient),
			httpbinding.WithAccept(func(method string) bool {
				return method == "orb" || method == "v1" || method == "elem" || method == "sov" ||
					method == "web" || method == "key" || method == "factom"
			}))
		if err != nil {
			return nil, fmt.Errorf("failed to create new universal resolver vdr: %w", err)
		}

		// add universal resolver vdr
		opts = append(opts, vdrpkg.WithVDR(didResolverVDRI))
	}

	if blocDomain != "" {
		vdr, err := orb.New(nil, orb.WithDomain(blocDomain), orb.WithHTTPClient(httpClient),
			orb.WithAuthToken(sidetreeToken))
		if err != nil {
			return nil, err
		}

		opts = append(opts, vdrpkg.WithVDR(vdr))
	}

	return vdrpkg.New(opts...), nil
}

type kmsProvider struct {
	storageProvider storage.Provider
	secretLock      secretlock.Service
}

func (k kmsProvider) StorageProvider() storage.Provider {
	return k.storageProvider
}

func (k kmsProvider) SecretLock() secretlock.Service {
	return k.secretLock
}
