/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.core.context;

import org.springframework.util.Assert;

/**
 * 这种存储模式适用于多线程环境，如果希望子线程中也能够获取到登录用户数据，那么可以使用这种存储模式
 *
 * An <code>InheritableThreadLocal</code>-based implementation of
 * {@link org.springframework.security.core.context.SecurityContextHolderStrategy}.
 *
 * @author Ben Alex
 * @see java.lang.ThreadLocal
 */
final class InheritableThreadLocalSecurityContextHolderStrategy implements SecurityContextHolderStrategy {

	// InheritableThreadLocal 继承自 ThreadLocal,但多了一个特性，在子线程创建的瞬间，会自动将父线程的数据复制到子线程中
	private static final ThreadLocal<SecurityContext> contextHolder = new InheritableThreadLocal<>();

	@Override
	public void clearContext() {
		contextHolder.remove();
	}

	@Override
	public SecurityContext getContext() {
		SecurityContext ctx = contextHolder.get();
		if (ctx == null) {
			ctx = createEmptyContext();
			contextHolder.set(ctx);
		}
		return ctx;
	}

	@Override
	public void setContext(SecurityContext context) {
		Assert.notNull(context, "Only non-null SecurityContext instances are permitted");
		contextHolder.set(context);
	}

	@Override
	public SecurityContext createEmptyContext() {
		return new SecurityContextImpl();
	}

}
