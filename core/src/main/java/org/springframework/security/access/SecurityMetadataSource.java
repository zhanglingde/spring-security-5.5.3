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

package org.springframework.security.access;

import java.util.Collection;

import org.springframework.aop.framework.AopInfrastructureBean;
import org.springframework.security.access.intercept.AbstractSecurityInterceptor;

/**
 * 安全元数据对象,提供访问安全受保护对象所需要的权限
 * 例如:访问一个 URL 地址,该 URL 地址需要哪些权限才能访问,由该对象提供
 *
 * Implemented by classes that store and can identify the {@link ConfigAttribute}s that
 * applies to a given secure object invocation.
 *
 * @author Ben Alex
 */
public interface SecurityMetadataSource extends AopInfrastructureBean {

	/**
	 * 根据传入的安全对象参数返回其所需要的权限。
	 * 如果受保护的对象是一个 URL 地址，那么传入的参数 object 就是 FilterInvocation 对象；
	 * 如果受保护的对象是一个方法，那么传入的参数 object 就是一个 MethodInvocation 对象
	 *
	 * Accesses the {@code ConfigAttribute}s that apply to a given secure object.
	 * @param object the object being secured
	 * @return the attributes that apply to the passed in secured object. Should return an
	 * empty collection if there are no applicable attributes.
	 * @throws IllegalArgumentException if the passed object is not of a type supported by
	 * the <code>SecurityMetadataSource</code> implementation
	 */
	Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException;

	/**
	 * 返回所有的角色/权限，以便验证是否支持。可以返回 null
	 *
	 * If available, returns all of the {@code ConfigAttribute}s defined by the
	 * implementing class.
	 * <p>
	 * This is used by the {@link AbstractSecurityInterceptor} to perform startup time
	 * validation of each {@code ConfigAttribute} configured against it.
	 * @return the {@code ConfigAttribute}s or {@code null} if unsupported
	 */
	Collection<ConfigAttribute> getAllConfigAttributes();

	/**
	 * 返回当前的 SecurityMetadataSource 是否支持受保护的对象如 FilterInvocation、MethodInvocation
	 *
	 * Indicates whether the {@code SecurityMetadataSource} implementation is able to
	 * provide {@code ConfigAttribute}s for the indicated secure object type.
	 * @param clazz the class that is being queried
	 * @return true if the implementation can process the indicated class
	 */
	boolean supports(Class<?> clazz);

}
