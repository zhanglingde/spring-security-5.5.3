/*
 * Copyright 2002-2013 the original author or authors.
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

package org.springframework.security.config.annotation;

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * A base {@link SecurityBuilder} that ensures the object being built is only built one
 * time.
 *
 * @param <O> the type of Object that is being built
 * @author Rob Winch
 *
 */
public abstract class AbstractSecurityBuilder<O> implements SecurityBuilder<O> {

	// 确保即使在多线程环境下，配置类也只构建一次
	private AtomicBoolean building = new AtomicBoolean();

	private O object;

	@Override
	public final O build() throws Exception {
		// 声明为 final ,确保子类不重写该方法，确保配置类只构建一次
		if (this.building.compareAndSet(false, true)) {
			// 具体构建
			this.object = doBuild();
			return this.object;
		}
		throw new AlreadyBuiltException("This object has already been built");
	}

	/**
	 * Gets the object that was built. If it has not been built yet an Exception is
	 * thrown.
	 * @return the Object that was built
	 */
	public final O getObject() {
		if (!this.building.get()) {
			throw new IllegalStateException("This object has not been built");
		}
		return this.object;
	}

	/**
	 * Subclasses should implement this to perform the build.
	 * @return the object that should be returned by {@link #build()}.
	 * @throws Exception if an error occurs
	 */
	protected abstract O doBuild() throws Exception;

}
