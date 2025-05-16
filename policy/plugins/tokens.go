// Copyright 2025 OpenPubkey
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/openpubkey/openpubkey/pktoken"
)

func PopulatePluginEnvVars(pkt *pktoken.PKToken, principal string, sshCert string, keyType string) (map[string]string, error) {
	pktCom, err := pkt.Compact()
	if err != nil {
		return nil, err
	}

	cicClaims, err := pkt.GetCicValues()
	if err != nil {
		return nil, err
	}
	upkJwk := cicClaims.PublicKey()
	upkJson, err := json.Marshal(upkJwk)
	if err != nil {
		return nil, err
	}
	upkB64 := base64.StdEncoding.EncodeToString(upkJson)

	type Claims struct {
		Issuer        string    `json:"iss"`
		Sub           string    `json:"sub"`
		Email         string    `json:"email"`
		EmailVerified *bool     `json:"email_verified"`
		Aud           Audience  `json:"aud"`
		Exp           *int64    `json:"exp"`
		Nbf           *int64    `json:"nbf"`
		Iat           *int64    `json:"iat"`
		Jti           string    `json:"jti"`
		Groups        *[]string `json:"groups"`
	}
	var claims Claims
	if err := json.Unmarshal(pkt.Payload, &claims); err != nil {
		return nil, fmt.Errorf("error unmarshalling pk token payload: %w", err)
	}

	groupsStr := ""
	if claims.Groups != nil {
		groupsStr = fmt.Sprintf(`["%s"]`, strings.Join(*claims.Groups, `","`))
	}

	emailVerifiedStr := ""
	if claims.EmailVerified != nil {
		emailVerifiedStr = fmt.Sprintf("%t", *claims.EmailVerified)
	}

	expStr := ""
	if claims.Exp != nil {
		expStr = fmt.Sprintf("%d", *claims.Exp)
	}

	nbfStr := ""
	if claims.Nbf != nil {
		nbfStr = fmt.Sprintf("%d", *claims.Nbf)
	}

	iatStr := ""
	if claims.Iat != nil {
		iatStr = fmt.Sprintf("%d", *claims.Iat)
	}

	tokens := map[string]string{
		"OPKSSH_PLUGIN_U": principal,
		"OPKSSH_PLUGIN_K": sshCert,
		"OPKSSH_PLUGIN_T": keyType,

		"OPKSSH_PLUGIN_ISS":            claims.Issuer,
		"OPKSSH_PLUGIN_SUB":            claims.Sub,
		"OPKSSH_PLUGIN_EMAIL":          claims.Email,
		"OPKSSH_PLUGIN_EMAIL_VERIFIED": emailVerifiedStr,
		"OPKSSH_PLUGIN_AUD":            string(claims.Aud),
		"OPKSSH_PLUGIN_EXP":            expStr,
		"OPKSSH_PLUGIN_NBF":            nbfStr,
		"OPKSSH_PLUGIN_IAT":            iatStr,
		"OPKSSH_PLUGIN_JTI":            claims.Jti,
		"OPKSSH_PLUGIN_GROUPS":         groupsStr,

		"OPKSSH_PLUGIN_PAYLOAD": string(b64(string(pkt.Payload))), // base64-encoded ID Token payload
		"OPKSSH_PLUGIN_UPK":     string(upkB64),                   // base64-encoded JWK of the user's public key
		"OPKSSH_PLUGIN_PKT":     string(pktCom),                   // compact-encoded PK Token
		"OPKSSH_PLUGIN_IDT":     string(pkt.OpToken),              // base64-encoded ID Token
	}

	return tokens, nil
}

type Audience string

func (a *Audience) UnmarshalJSON(data []byte) error {
	var multi []string
	if err := json.Unmarshal(data, &multi); err == nil {
		*a = Audience(`["` + strings.Join(multi, `","`) + `"]`)
		return nil
	}

	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*a = Audience(single)
		return nil
	} else {
		return err
	}

}
