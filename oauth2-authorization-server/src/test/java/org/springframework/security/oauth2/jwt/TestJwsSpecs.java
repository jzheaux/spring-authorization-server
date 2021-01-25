/*
 * Copyright 2020-2021 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.jwt;

import java.time.Instant;

import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.util.Assert;

public class TestJwsSpecs {
	public static Jwt.JwsSpec<?> jwsSpec() {
		return jwsSpec("token");
	}

	public static Jwt.JwsSpec<?> jwsSpec(String tokenValue) {
		return new MockJwsSpec(tokenValue)
				.algorithm(SignatureAlgorithm.RS256)
				.issuedAt(Instant.now())
				.expiresAt(Instant.now().plusSeconds(3600));
	}

	private static class MockJwsSpec extends Jwt.JwtSpecSupport<MockJwsSpec>
			implements Jwt.JwsSpec<MockJwsSpec> {

		private String tokenValue;

		MockJwsSpec(String tokenValue) {
			this.tokenValue = tokenValue;
		}

		@Override
		public Jwt sign() {
			Instant issuedAt = toInstant(this.claims.get(JwtClaimNames.IAT));
			Instant expiresAt = toInstant(this.claims.get(JwtClaimNames.EXP));
			return new Jwt(this.tokenValue, issuedAt, expiresAt, this.headers, this.claims);
		}

		private Instant toInstant(Object timestamp) {
			if (timestamp != null) {
				Assert.isInstanceOf(Instant.class, timestamp, "timestamps must be of type Instant");
			}
			return (Instant) timestamp;
		}
	}
}
